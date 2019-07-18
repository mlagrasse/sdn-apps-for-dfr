# Copyright (C) 2019 mlagrasse.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import array
import requests
from collections import defaultdict

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import snortlib
from ryu.lib.packet import packet, ethernet, ipv4, ipv6, icmp


class SimpleSwitchSnortOutOfBand(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnortOutOfBand, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 3
        nested_dict = lambda: defaultdict(nested_dict)
        self.mac_to_port = nest = nested_dict()
        self.vlan10 = [
            1,4,6,7
            ]
        self.vlan20 = [
            2,3,5
            ]
        #self.DFR_storage_ip = "10.0.1.4"

        socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _ipv6 = pkt.get_protocol(ipv6.ipv6)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if _ipv6:
            self.logger.info("%r", _ipv6)

        if eth:
            self.logger.info("%r", eth)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        pkt = packet.Packet(array.array('B', msg.pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _ipv6 = pkt.get_protocol(ipv6.ipv6)

        print('alertmsg: %s' % ''.join(msg.alertmsg))
        self.packet_print(msg.pkt)

        # This is where the DFR process starts
        if _ipv4:
            ip_src = _ipv4.src
            ip_dst = _ipv4.src
        elif _ipv6:
            ip_src = _ipv6.src
            ip_dst = _ipv6.src

        data = {"user": "root",
                "source_ip": ip_src,
                "destination_ip": ip_dst,
                "source_mac": eth.src,
                "destination_mac": eth.dst
               }
        headers = { 'Api-Secret-Key': 'UsXT23mk5', 'Api-Token': 'SlWwFZ4tNuKTIB9ZQ4EeuCfRWbCzvK0a',
                    'Api-Key': 'UsXT23mk5.SlWwFZ4tNuKTIB9ZQ4EeuCfRWbCzvK0a', 'Authorization': 'Api-Key UsXT23mk5.SlWwFZ4tNuKTIB9ZQ4EeuCfRWbCzvK0a'}
        files={'pde': msg.pkt}
        # Sends the PDE to the storage server
        r = requests.post("https://10.0.1.4/pde/add/", data=data, headers=headers, files=files, verify=False)
        if "Success" not in r.text:
            self.logger.info("Failed to store the PDE on the storage server.")
        elif "Success" in r.text:
            self.logger.info("Successfully stored the PDE on the storage server.")
        self.logger.info('Message from storage server: ' + r.text)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # This function can be used in order to quarantine the machine from
    # where the attack is originating
    def add_blocking_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # Learn a mac address to avoid FLOOD next time, ensuring control
        # plane and data plane are isolated
        if in_port in self.vlan10:
            vlan='vlan10'
            ports_list=self.vlan10
        elif in_port in self.vlan20:
            vlan='vlan20'
            ports_list=self.vlan20

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][vlan][src] = in_port

        if dst in self.mac_to_port[dpid][vlan]:
            out_port = self.mac_to_port[dpid][vlan][dst]
            actions = [parser.OFPActionOutput(self.snort_port),
            parser.OFPActionOutput(out_port)]

            # Install a flow to avoid packet_in next time
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        else:
            # Avoid putting snort_port twice in the list of output ports
            if self.snort_port not in ports_list:
                actions=[parser.OFPActionOutput(self.snort_port)]
            else:
                actions=[]
            # Broadcasting packet to all ports in the vlan
            for out_port in ports_list:
                actions.append(parser.OFPActionOutput(out_port))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
