"""Main module of amlight/kytos_flow_manager Kytos Network Application.

# TODO: <<<< Insert here your NApp description >>>>
"""

from kytos.core import KytosNApp, log
from kytos.core.helpers import listen_to
from flask import request
from napps.amlight.sdntrace import constants
from pyof.v0x01.common.flow_match import FlowWildCards
from pyof.v0x01.common.action import ActionType
from pyof.v0x01.controller2switch.flow_mod import FlowMod as FlowMod10
from pyof.v0x04.controller2switch.flow_mod import FlowMod as FlowMod13
from pyof.foundation.network_types import Ethernet, IPv4
import pyof.v0x01.controller2switch.common
from napps.amlight.sdntrace.shared.switches import Switches
from napps.amlight.kytos_flow_manager.utils import Flows, ACTION_TYPES
from napps.amlight.sdntrace.shared.extd_nw_types import VLAN, TCP, UDP
from napps.amlight.kytos_flow_manager import settings
import json, dill
import ipaddress


class GenericFlow(object):

    def __init__(self, version=0x01, in_port=0, phy_port=None, eth_src=None, eth_dst=None, eth_type=None, vlan_vid=None,
                 vlan_pcp=None, ip_tos=None, ip_dscp=None, ip_ecn=None, ip_proto=None, ipv4_src=None, ipv4_dst=None,
                 ipv6_src=None, ipv6_dst=None, tcp_src=None, tcp_dst=None, udp_src=None, udp_dst=None, sctp_src=None,
                 sctp_dst=None, icmpv4_type=None, icmpv4_code=None, arp_op=None, arp_spa=None, arp_tpa=None,
                 arp_sha=None, arp_tha=None, ipv6_flabel=None, icmpv6_type=None, icmpv6_code=None, ipv6_nd_target=None,
                 ipv6_nd_sll=None, ipv6_nd_tll=None, mpls_label=None, mpls_tc=None, mpls_bos=None, pbb_isid=None,
                 tunnel_id=None, ipv6_exthdr=None, wildcards=None, idle_timeout=0, hard_timeout=0, duration_sec=0,
                 packet_count=0, byte_count=0, priority=0, table_id=0xff, cookie=None, buffer_id=None, actions=None):
        self.version = version
        self.in_port = in_port
        self.phy_port = phy_port
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.eth_type = eth_type
        self.vlan_vid = vlan_vid
        self.vlan_pcp = vlan_pcp
        self.ip_tos = ip_tos
        self.ip_dscp = ip_dscp
        self.ip_ecn = ip_ecn
        self.ip_proto = ip_proto
        self.ipv4_src = ipv4_src
        self.ipv4_dst = ipv4_dst
        self.ipv6_src = ipv6_src
        self.ipv6_dst = ipv6_dst
        self.tcp_src = tcp_src
        self.tcp_dst = tcp_dst
        self.udp_src = udp_src
        self.udp_dst = udp_dst
        self.sctp_src = sctp_src
        self.sctp_dst = sctp_dst
        self.icmpv4_type = icmpv4_type
        self.icmpv4_code = icmpv4_code
        self.arp_op = arp_op
        self.arp_spa = arp_spa
        self.arp_tpa = arp_tpa
        self.arp_sha = arp_sha
        self.arp_tha = arp_tha
        self.ipv6_flabel = ipv6_flabel
        self.icmpv6_type = icmpv6_type
        self.icmpv6_code = icmpv6_code
        self.ipv6_nd_target = ipv6_nd_target
        self.ipv6_nd_sll = ipv6_nd_sll
        self.ipv6_nd_tll = ipv6_nd_tll
        self.mpls_label = mpls_label
        self.mpls_tc = mpls_tc
        self.mpls_bos = mpls_bos
        self.pbb_isid = pbb_isid
        self.tunnel_id = tunnel_id
        self.ipv6_exthdr = ipv6_exthdr
        self.wildcards = wildcards
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.duration_sec = duration_sec
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.priority = priority
        self.table_id = table_id
        self.cookie = cookie
        self.buffer_id = buffer_id
        self.actions = actions

    @property
    def id(self):
        return self.duration_sec

    def to_dict(self):
        flow_dict = {}
        flow_dict['version'] = self.version
        flow_dict['in_port'] = self.in_port
        flow_dict['phy_port'] = self.phy_port
        flow_dict['eth_src'] = self.eth_src
        flow_dict['eth_dst'] = self.eth_dst
        flow_dict['eth_type'] = self.eth_type
        flow_dict['vlan_vid'] = self.vlan_vid
        flow_dict['vlan_pcp'] = self.vlan_pcp
        flow_dict['ip_tos'] = self.ip_tos
        flow_dict['ip_dscp'] = self.ip_dscp
        flow_dict['ip_ecn'] = self.ip_ecn
        flow_dict['ip_proto'] = self.ip_proto
        flow_dict['ipv4_src'] = self.ipv4_src
        flow_dict['ipv4_dst'] = self.ipv4_dst
        flow_dict['ipv6_src'] = self.ipv6_src
        flow_dict['ipv6_dst'] = self.ipv6_dst
        flow_dict['tcp_src'] = self.tcp_src
        flow_dict['tcp_dst'] = self.tcp_dst
        flow_dict['udp_src'] = self.udp_src
        flow_dict['udp_dst'] = self.udp_dst
        flow_dict['sctp_src'] = self.sctp_src
        flow_dict['sctp_dst'] = self.sctp_dst
        flow_dict['icmpv4_type'] = self.icmpv4_type
        flow_dict['icmpv4_code'] = self.icmpv4_code
        flow_dict['arp_op'] = self.arp_op
        flow_dict['arp_spa'] = self.arp_spa
        flow_dict['arp_tpa'] = self.arp_tpa
        flow_dict['arp_sha'] = self.arp_sha
        flow_dict['arp_tha'] = self.arp_tha
        flow_dict['ipv6_flabel'] = self.ipv6_flabel
        flow_dict['icmpv6_type'] = self.icmpv6_type
        flow_dict['icmpv6_code'] = self.icmpv6_code
        flow_dict['ipv6_nd_target'] = self.ipv6_nd_target
        flow_dict['ipv6_nd_sll'] = self.ipv6_nd_sll
        flow_dict['ipv6_nd_tll'] = self.ipv6_nd_tll
        flow_dict['mpls_label'] = self.mpls_label
        flow_dict['mpls_tc'] = self.mpls_tc
        flow_dict['mpls_bos'] = self.mpls_bos
        flow_dict['pbb_isid'] = self.pbb_isid
        flow_dict['tunnel_id'] = self.tunnel_id
        flow_dict['ipv6_exthdr'] = self.ipv6_exthdr
        flow_dict['wildcards'] = self.wildcards
        flow_dict['idle_timeout'] = self.idle_timeout
        flow_dict['hard_timeout'] = self.hard_timeout
        flow_dict['priority'] = self.priority
        flow_dict['table_id'] = self.table_id
        flow_dict['cookie'] = self.cookie
        flow_dict['buffer_id'] = self.buffer_id
        flow_dict['actions'] = []
        for action in self.actions:
            action_dict = {}
            for attr_key, attr_value in action.__dict__.items():
                action_dict[attr_key] = '%s' % attr_value
            flow_dict['actions'].append(action_dict)

        return flow_dict

    def to_json(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def from_dict(flow_dict):
        flow = GenericFlow()
        for attr_name, value in flow_dict.items():
            if attr_name == 'actions':
                flow.actions = []
                for action in value:
                    new_action = ACTION_TYPES[int(action['action_type'])]()
                    for action_attr_name, action_attr_value in action.items():
                        setattr(new_action, action_attr_name, action_attr_value)
                    flow.actions.append(new_action)
            else:
                setattr(flow, attr_name, value)
        return flow

    @classmethod
    def from_flow_stats(cls, flow_stats, version=0x01):
        flow = GenericFlow(version=version)
        if version == 0x01:
            flow.idle_timeout = flow_stats.idle_timeout.value
            flow.hard_timeout = flow_stats.hard_timeout.value
            flow.priority = flow_stats.priority.value
            flow.table_id = flow_stats.table_id.value
            flow.wildcards = flow_stats.match.wildcards.value
            flow.in_port = flow_stats.match.in_port.value
            flow.eth_src = flow_stats.match.dl_src.value
            flow.eth_dst = flow_stats.match.dl_dst.value
            flow.vlan_vid = flow_stats.match.dl_vlan.value
            flow.vlan_pcp = flow_stats.match.dl_vlan_pcp.value
            flow.eth_type = flow_stats.match.dl_type.value
            flow.ip_tos = flow_stats.match.nw_tos.value
            flow.ipv4_src = flow_stats.match.nw_src.value
            flow.ipv4_dst = flow_stats.match.nw_dst.value
            flow.tcp_src = flow_stats.match.tp_src.value
            flow.tcp_dst = flow_stats.match.tp_dst.value
            flow.duration_sec = flow_stats.duration_sec.value
            flow.packet_count = flow_stats.packet_count.value
            flow.byte_count = flow_stats.byte_count.value
            flow.actions = []
            for action in flow_stats.actions:
                flow.actions.append(action)
        return flow

    def match(self, args):
        if self.version == 0x01:
            return self.match10(args)
        elif self.version == 0x04:
            return self.match13(args)

    def match10(self, args):
        log.debug('Matching packet')
        if not self.wildcards & FlowWildCards.OFPFW_IN_PORT:
            if not 'in_port' in args:
                return False
            if self.in_port != int(args['in_port']):
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_VLAN_PCP:
            if not 'vlan_pcp' in args:
                return False
            if self.vlan_pcp != int(args['vlan_pcp']):
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_VLAN:
            if not 'vlan_vid' in args:
                return False
            if self.vlan_vid != int(args['vlan_vid']):
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_SRC:
            if not 'eth_src' in args:
                return False
            if self.eth_src != args['eth_src']:
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_DST:
            if not 'eth_dst' in args:
                return False
            if self.eth_dst != args['eth_dst']:
                return False
        log.info('I\'m here 5')
        if not self.wildcards & FlowWildCards.OFPFW_DL_TYPE:
            if not 'eth_type' in args:
                return False
            if self.eth_type != int(args['eth_type']):
                return False
        if self.eth_type == constants.IPv4:
            flow_ip_int = int(ipaddress.IPv4Address(self.ipv4_src))
            if flow_ip_int != 0:
                mask = (self.wildcards & FlowWildCards.OFPFW_NW_SRC_MASK) >> FlowWildCards.OFPFW_NW_SRC_SHIFT
                if mask > 32:
                    mask = 32
                if mask != 32 and not 'ipv4_src' in args:
                    return False
                mask = (0xffffffff << mask) & 0xffffffff
                ip_int = int(ipaddress.IPv4Address(args['ipv4_src']))
                if ip_int & mask != flow_ip_int & mask:
                    return False

            flow_ip_int = int(ipaddress.IPv4Address(self.ipv4_dst))
            if flow_ip_int != 0:
                mask = (self.wildcards & FlowWildCards.OFPFW_NW_DST_MASK) >> FlowWildCards.OFPFW_NW_DST_SHIFT
                if mask > 32:
                    mask = 32
                if mask != 32 and not 'ipv4_dst' in args:
                    return False
                mask = (0xffffffff << mask) & 0xffffffff
                ip_int = int(ipaddress.IPv4Address(args['ipv4_dst']))
                if ip_int & mask != flow_ip_int & mask:
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_NW_TOS:
                if not 'ip_tos' in args:
                    return False
                if self.ip_tos != int(args['ip_tos']):
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_NW_PROTO:
                if not 'ip_proto' in args:
                    return False
                if self.ip_proto != int(args['ip_proto']):
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_TP_SRC:
                if not 'tp_src' in args:
                    return False
                if self.tcp_src != int(args['tp_src']):
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_TP_DST:
                if not 'tp_dst' in args:
                    return False
                if self.tcp_dst != int(args['tp_dst']):
                    return False

        # for action in self.actions:
        #     if action.action_type == ActionType.OFPAT_OUTPUT:
        #         return '%s' % action.port.value
        return self.to_dict()

    def match13(self, args):
        pass


class Main(KytosNApp):
    """Main class of amlight/kytos_flow_manager NApp.

    This class is the entry point for this napp.
    """

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        So, if you have any setup routine, insert it here.
        """
        log.info('Starting Kytos/Amlight flow manager')
        self.register_rest()

    def register_rest(self):
        """Register REST calls
        POST /flow/match/<dpid> tries to match a packet with a switch (identified by dpid) flows
        GET /flows/packet_count/<dpid>?start_date=0&end_date=0
        GET /flows/byte_count/<dpid>?start_date=0&end_date=0
        Returns packet or byte counters from start to end date, for each flow in a switch (identified by dpid)
        """
        endpoints = [
            ('/flow/match/<dpid>', self.flow_match, ['GET']),
            ('/flow/stats/<dpid>', self.flow_stats, ['GET']),
            ('/flow/packet_count/<dpid>', self.packet_count, ['GET']),
            ('/flow/byte_count/<dpid>', self.byte_count, ['GET']),
        ]

        for endpoint in endpoints:
            self.controller.register_rest_endpoint(*endpoint)

    def execute(self):
        """This method is executed right after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.
        """
        pass

    def shutdown(self):
        """This method is executed when your napp is unloaded.

        If you have some cleanup procedure, insert it here.
        """
        pass

    def flow_match(self, dpid):
        return self.match_flows(dpid, False)

    def flow_stats(self, dpid):
        return self.match_flows(dpid, True)

    def match_flows(self, dpid, many=True):
        """
        Tries to match the packet in request against the flows installed in switch with given dpid.
        Tries the match with each flow, in other. If many is True, tries the match with all flows, if False,
        tries until the first match.
        :param dpid: DPID of the switch
        :param many: Boolean, indicating whether to continue after matching the first flow or not
        :return: If many, the list of matched flows, or the matched flow
        """
        args = request.args

        flows = Flows().get_flows(dpid)
        response = []
        for flow in flows:
            m = flow.match(args)
            if m:
                if many:
                    response.append(m)
                else:
                    response = m
                    break
        return json.dumps({'response': response}), 200

    def packet_count(self, dpid):
        return self.count('packet_count', dpid)

    def byte_count(self, dpid):
        return self.count('byte_count', dpid)

    def count(self, field, dpid):
        start_date = request.args.get('start_date', 0)
        end_date = request.args.get('end_date', 0)

        count_flows = []
        # We don't have statistics persistence yet, so for now this only works for start and end equals to zero
        flows = Flows().get_flows(dpid)

        for flow in flows:
            count = getattr(flow, field)
            count_flows.append({'flow_id': flow.id,
                                field: count,
                                '%s_rate' % field: count/flow.duration_sec})

        return json.dumps(count_flows)


    @staticmethod
    def break_packet(pkt):
        ethernet = Ethernet()
        ethernet.unpack(pkt)
        ether_type = ethernet.ether_type
        offset = 0

        if ethernet.ether_type == constants.VLAN:
            vlan = VLAN()
            vlan.unpack(ethernet.data.value)
            ether_type = vlan.ether_type
            offset += constants.VLAN_LEN
        else:
            vlan = None

        ip = None
        if ether_type == constants.IPv4:
            ip = IPv4()
            ip.unpack(ethernet.data.value, offset)
            offset += ip.length
        elif ether_type == 'IPv6': #TODO
            pass

        tp = None
        if ether_type == constants.IPv4: #TODO: add IPv6 with an or
            if ip.protocol == constants.TCP:
                tp = TCP()
                tp.parse(ethernet.data.alue, offset)
                offset += tp.length
            elif ip.protocol == constants.UDP:
                tp = UDP()
                tp.parse(ethernet.data.alue, offset)
                offset += tp.length

        return ethernet, vlan, ip, tp

    @staticmethod
    @listen_to('kytos/of_core.v0x01.messages.in.ofpt_stats_reply')
    def handle_features_reply(event):
        msg = event.content['message']
        if msg.body_type == pyof.v0x01.controller2switch.common.StatsTypes.OFPST_FLOW:
            switch = event.source.switch
            Flows().clear(switch.dpid)
            i = 0
            for flow_stats in msg.body:
                i += 1
                flow = GenericFlow.from_flow_stats(flow_stats)
                Flows().add_flow(switch.dpid, flow)
            Flows().sort(switch.dpid)