"""Main module of ajoaoff/coloring Kytos Network Application.

NApp to color a network topology
"""

from kytos.core import KytosEvent, KytosNApp, log
from kytos.core.flow import Flow
from kytos.core.helpers import listen_to
from kytos.core.switch import Interface
from napps.ajoaoff.coloring import settings
import requests
import json
import struct


class Main(KytosNApp):
    """Main class of ajoaoff/coloring NApp.

    This class is the entry point for this napp.
    """

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        So, if you have any setup routine, insert it here.
        """
        self.switches = {}
        self.register_rest()
        self.execute_as_loop(settings.COLORING_INTERVAL)

    def execute(self):
        """This method is executed right after the setup method execution.

            Color each switch, with the color based on the switch's DPID.
            After that, if not yet installed, installs, for each switch, flows
            with the color of its neighbors, to send probe packets to the
            controller.
        """
        url = 'http://localhost:8181/kytos/flow-manager/flows/%s'

        # First, set the color of all the switches, if not already set
        for switch in self.controller.switches.values():
            if switch.dpid not in self.switches:
                color = int(switch.dpid.replace(':', '')[4:], 16)
                self.switches[switch.dpid] = {'color': color, 'neighbors': [], 'flows': []}
            else:
                self.switches[switch.dpid]['neighbors'] = []

            # Calculate all neighbors of a switch, based on the topology
            for interface in switch.interfaces.values():
                for endpoint, _ in interface.endpoints:
                    if isinstance(endpoint, Interface):
                        self.switches[switch.dpid]['neighbors'].append(endpoint.switch)

        # Create the flows for each neighbor of each switch and installs it if not already
        # installed
        for dpid, switch_dict in self.switches.items():
            for neighbor in switch_dict['neighbors']:
                flow_dict = {'idle_timeout': 0, 'hard_timeout': 0, 'table_id': 0, 'buffer_id': None,
                             'in_port': 0, 'dl_src': '00:00:00:00:00:00', 'dl_dst': '00:00:00:00:00:00',
                             'dl_vlan': 0, 'dl_type': 0, 'nw_src': '0.0.0.0', 'nw_dst': '0.0.0.0',
                             'tp_src': 0, 'tp_dst': 0, 'priority': 50000,
                             'actions': [{'port': 65533}]}
                flow_dict[settings.COLOR_FIELD] = self.color_to_field(self.switches[neighbor.dpid]['color'],
                                                                      settings.COLOR_FIELD)
                flow = Flow.from_dict(flow_dict)
                if flow not in switch_dict['flows']:
                    switch_dict['flows'].append(flow)
                    r = requests.post(url % dpid, json=[flow.as_dict()['flow']])
                    if r.status_code // 100 != 2:
                        log.error('Flow manager returned an error inserting flow. Status code %s, flow id %s.' %
                                  (r.status_code, flow.id))
            log.info('Switch %s, flows %s' % (dpid, [f.as_dict() for f in switch_dict['flows']]))
        log.info('Switches %s' % self.switches)

    def shutdown(self):
        """This method is executed when your napp is unloaded.

        If you have some cleanup procedure, insert it here.
        """
        pass

    def register_rest(self):
        endpoints = [('/coloring/colors', self.rest_colors, ['GET'])]
        for endpoint in endpoints:
            self.controller.register_rest_endpoint(*endpoint)

    @staticmethod
    @listen_to('kytos/of_core.messages.in.ofpt_port_status')
    def update_link_on_port_status_change(event):
        port_status = event.message
        reasons = ['CREATED', 'DELETED', 'MODIFIED']
        switch = event.source.switch
        port_no = port_status.desc.port_no
        reason = reasons[port_status.reason.value]

        if reason is 'MODIFIED':
            interface = switch.get_interface_by_port_no(port_no.value)
            for endpoint, _ in interface.endpoints:
                if isinstance(endpoint, Interface):
                    interface.delete_endpoint(endpoint)

    @staticmethod
    def color_to_field(color, field='dl_src'):
        """
        Gets the color number and returns it in a format suitable for the field
        :param color: The color of the switch (integer)
        :param field: The field that will be used to create the flow for the color
        :return: A representation of the color suitable for the given field
        """
        # TODO: calculate field value for other fields
        if field == 'dl_src' or field == 'dl_dst':
            c = color & 0xffffffffffffffff
            int_mac = struct.pack('!Q', c)[2:]
            return ':'.join(['%02x' % b for b in int_mac])
        if field == 'nw_src' or field == 'nw_dst':
            c = color & 0xffffffff
            int_ip = struct.pack('!L', c)
            return '.'.join(map(str, int_ip))
        if field == 'in_port' or field == 'dl_vlan' or field == 'tp_src' or field == 'tp_dst':
            c = color & 0xffff
            return c
        if field == 'nw_tos' or field == 'nw_proto':
            c = color & 0xff
            return c

    def rest_colors(self):
        colors = {}
        for dpid, switch_dict in self.switches.items():
            colors[dpid] = {'color_field': settings.COLOR_FIELD,
                            'color_value': switch_dict['color']}
        return json.dumps({'colors': colors})