from kytos.core import log
from napps.amlight.sdntrace.shared.singleton import Singleton


class Flows(metaclass=Singleton):
    """Class to store all flows installed in the switches
    """
    def __init__(self):
        self._flows = dict()

    def clear(self, dpid):
        self._flows[dpid] = list()

    def add_flow(self, dpid, flow):
        if dpid not in self._flows:
            self._flows[dpid] = list()
        self._flows[dpid].append(flow)

    def get_flows(self, dpid):
        if dpid in self._flows:
            return self._flows[dpid]

