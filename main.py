__author__ = "Grant Curell"
__copyright__ = "Do what you want with it"
__license__ = "Unlicense"
__version__ = "1.0.0"
__maintainer__ = "Grant Curell"

import json
import sys
import urllib3
import logging
from webob import Response, Request
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, tcp, udp, icmp
from ryu.app.wsgi import WSGIApplication, route
from ryu.app.ofctl_rest import StatsController, RestStatsApi
from ryu.cmd import manager
from collections import defaultdict
from typing import List

ryu_instance = 'ryu_app'


def remove_all_flows(datapath: Datapath):
    """
    Removes all the flows from a switch.

    :param datapath: A Datapath object which represents the switch from which we want to remove flows
    """

    match = datapath.ofproto_parser.OFPMatch()
    mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, datapath.ofproto.OFPTT_ALL,
                                             datapath.ofproto.OFPFC_DELETE,
                                             0, 0, 0, 0xffffffff,
                                             datapath.ofproto.OFPP_ANY,
                                             datapath.ofproto.OFPG_ANY,
                                             0, match, [])

    datapath.send_msg(mod)


def add_flow(datapath: Datapath, priority: int, match: OFPMatch, actions: [OFPActionOutput], idle_timeout: int = 300,
             hard_timeout: int = 300):
    """
    Send a flow to the switch to be added to the flow table

    :param datapath: A Datapath object which represents the switch to which we want to add the flow
    :param priority: The priority of the flow. Should be higher than zero. Zero is the default flow used when traffic
                     does not match and should be sent to the controller.
    :param match: An OFPMatch object containing the match criteria for this flow
    :param actions: The actions you want applied if there is a flow match.
    :param idle_timeout: The timeout for the flow if the switch receives no matching packets. 0 is no timeout.
    :param hard_timeout: The timeout for the flow regardless if the switch does or doesn't receive packets.
                         0 is no timeout.
    """

    ofproto = datapath.ofproto

    # Same as ofproto, indicates the ofproto_parser module. In the case of OpenFlow 1.3 format will be following
    # module. ryu.ofproto.ofproto_v1_3_parser
    parser = datapath.ofproto_parser

    # construct flow_mod message and send it.
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                         actions)]

    # The class corresponding to the Flow Mod message is the OFPFlowMod class. The instance of the OFPFlowMod
    # class is generated and the message is sent to the OpenFlow switch using the Datapath.send_msg() method.
    mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                            idle_timeout=idle_timeout, hard_timeout=hard_timeout)
    datapath.send_msg(mod)


def get_packet_type(pkt: packet.Packet) -> dict:
    """
    Returns a dictionary containing a packet's type

    :param pkt: The packet whose data we want to evaluate
    :return: A dictionary containing the packet's metadata. The packet's type will be stored under the "type" key.
    """

    pkt_metadata = {}
    pkt_metadata["type"] = "unsupported"

    for index, protocol in enumerate(pkt.protocols, start=0):
        if type(protocol) == ipv4.ipv4:
            pkt_metadata["ipv4"] = index
            pkt_metadata["ipv4_src"] = protocol.src
            pkt_metadata["ipv4_dst"] = protocol.dst
        elif type(protocol) == tcp.tcp:
            pkt_metadata["type"] = "tcp"
            pkt_metadata["tcp"] = index
            pkt_metadata["transport_layer"] = index  # Works for both TCP and UDP
            pkt_metadata["src_port"] = protocol.src_port
            pkt_metadata["dst_port"] = protocol.dst_port
        elif type(protocol) == udp.udp:
            pkt_metadata["type"] = "udp"
            pkt_metadata["udp"] = index
            pkt_metadata["transport_layer"] = index  # Works for both TCP and UDP
            pkt_metadata["src_port"] = protocol.src_port
            pkt_metadata["dst_port"] = protocol.dst_port
        elif type(protocol) == icmp.icmp:
            pkt_metadata["type"] = "icmp"
            pkt_metadata["icmp"] = index
            pkt_metadata["icmp_type"] = protocol.type
            pkt_metadata["icmp_code"] = protocol.code

    return pkt_metadata


def set_destination(pkt: packet.Packet, dest_ip: str) -> packet.Packet:
    """
    Change ethe destination IP of a selected packet

    :param pkt: The packet which you want to update
    :param dest_ip: The IP address of the revised destination
    :return: The modified packet
    """

    for index, protocol in enumerate(pkt.protocols, start=0):
        if type(protocol) == ipv4.ipv4:
            pkt.protocols[index].dst = dest_ip
            break

    return pkt


def create_response(req: Request, body: str = None, content_type: str = "application/json") -> Response:
    """
    Responds to Cross-origin resource sharing (CORS) requests. Only permits responses to localhost.

    :param body: The body of the request object that has been sent
    :param content_type: The content type of the response
    :param req: The inbound HTTP request in which we want to check for a CORS header
    :return: Returns a list of headers including a valid CORS response if the request came from the localhost and the
             HTTP origin was specified otherwise returns an empty list.

    """

    environ = req.headers.environ

    method = environ.get("REQUEST_METHOD")
    origin = environ.get("HTTP_ORIGIN")
    cookie = environ.get("HTTP_COOKIE", "N/A")
    logging.info("")
    logging.info("Method: " + method + " Path: " + environ["PATH_INFO"])
    if origin:
        logging.info("Origin: " + origin)
    if cookie:
        logging.info("Cookie: " + cookie)

    cors = origin
    preflight = cors and method == "OPTIONS"

    headers = [("Content-Type", content_type)]

    headers.extend([
        ("Access-Control-Allow-Origin", origin),
        ("Access-Control-Allow-Credentials", "true")
    ])
    if preflight:
        headers.extend([
            ("Access-Control-Allow-Methods", "PUT, GET"),
            ("Access-Control-Allow-Headers", "Content-Type")
        ])
    else:
        headers.append(("Set-Cookie", "auth=fnd"))

    if method == "OPTIONS":
        return Response(status=204, headerlist=headers)
    else:
        return Response(content_type=content_type, text=body, headerlist=headers, status=200)


class RyuController:
    """
    This is the main Ryu app that is the Ryu controller

    In order to implement as a Ryu application, ryu.base.app_manager.RyuApp is inherited. Also, to use OpenFlow 1.3, the
    OpenFlow 1.3 version is specified for OFP_VERSIONS.

    Attributes:
        mac_to_port (dict): Used to store information mapping MAC addresses to a specific port
        flow_table (dict): Used to store flow information mapped to a specific port. If the controller receives a packet
                           not already associated with a flow, it creates a flow entry and then maps it to an outbound
                           port
        round_robin (int): Used to keep track of the next port a flow should be assigned to. We use this to load balance
                           flows across multiple ports.
        switches (dict): A dictionary of form {dpid: Datapath} with all of the devices being managed by this controller
        in_ports (defaultdict): Used to keep track of all ports expected to be used for inbound traffic.
        out_ports (defaultdict): Used to keep track of all the ports used for outbound traffic

    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RyuController, self).__init__(*args, **kwargs)
        # mac_to_port is the MAC address table for the switch
        self.mac_to_port = {}
        self.flow_table = {}
        self.round_robin = 0
        self.switches = {}
        self.in_ports = defaultdict(list)
        self.out_ports = defaultdict(list)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        See https://osrg.github.io/ryu-book/en/html/switching_hub.html#event-handler for description.
        See https://osrg.github.io/ryu-book/en/html/switching_hub.html#adding-table-miss-flow-entry for the rest of the
        function details.

        This function handles the ryu.controller.handler.CONFIG_DISPATCHER state. This state is used to handle waiting
        to receive SwitchFeatures message.

        :param ev: The switch event object containing the message data For this function we expect an instance of
                   ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
        :return:
        """

        # In datapath we expect the instance of the ryu.controller.controller.Datapath class corresponding to the
        # OpenFlow switch that issued this message is stored. The Datapath class performs important processing such as
        # actual communication with the OpenFlow switch and issuance of the event corresponding to the received message.
        datapath = ev.msg.datapath

        # Indicates the ofproto module that supports the OpenFlow version in use. In the case of OpenFlow 1.3 format
        # will be following module. ryu.ofproto.ofproto_v1_3
        ofproto = datapath.ofproto

        # Same as ofproto, indicates the ofproto_parser module. In the case of OpenFlow 1.3 format will be following
        # module. ryu.ofproto.ofproto_v1_3_parser
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        # The Table-miss flow entry has the lowest (0) priority and this entry matches all packets. In the instruction
        # of this entry, by specifying the output action to output to the controller port, in case the received packet
        # does not match any of the normal flow entries, Packet-In is issued.
        #
        # An empty match is generated to match all packets. Match is expressed in the OFPMatch class.
        #
        # Next, an instance of the OUTPUT action class (OFPActionOutput) is generated to transfer to the controller
        # port. The controller is specified as the output destination and OFPCML_NO_BUFFER is specified to max_len in
        # order to send all packets to the controller.
        match = parser.OFPMatch()

        actions: List[OFPActionOutput] = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # Clear out all existing flows on the switch before continuing
        # TODO you may want to remove this
        remove_all_flows(datapath)

        # Finally, 0 (lowest) is specified for priority and the add_flow() method is executed to send the Flow Mod
        # message. The content of the add_flow() method is explained in a later section.
        add_flow(datapath, 0, match, actions, 0, 0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        See https://osrg.github.io/ryu-book/en/html/switching_hub.html#event-handler for description.

        This function handles the ryu.controller.handler.MAIN_DISPATCHER state. This state is used to handle a new
        inbound packet

        :param ev: The event containing the packet data.
        """

        msg = ev.msg
        datapath = msg.datapath

        # Same as ofproto, indicates the ofproto_parser module. In the case of OpenFlow 1.3 format will be following
        # module. ryu.ofproto.ofproto_v1_3_parser
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id  # 64-bit OpenFlow Datapath ID of the switch to which the port belongs.

        # Get the OpenFlow protocol in use.
        ofproto = datapath.ofproto

        self.mac_to_port.setdefault(dpid, {})

        in_port = msg.match['in_port']

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)

        pkt_metadata = get_packet_type(pkt)

        # Check to see if the packet is a HTTP packet and if it is reroute it
        if pkt_metadata["type"] == "tcp" and (pkt_metadata["src_port"] == 80 or pkt_metadata["dst_port"] == 80):

            pkt = set_destination(pkt, "192.168.1.6")  # TODO put your updated IP here

            # construct action list.
            # TODO - this is the physical port to which you want to output. You will need to update this
            # The mapping of physical ports -> openflow port numbers is available in datapath.ports
            # See: https://stackoverflow.com/questions/60939750/ryu-openflow-how-to-map-in-port-number-to-physical-port/61410039#61410039
            actions = [parser.OFPActionOutput(5)]

            # Convert the packet back to raw binary
            pkt.serialize()

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                      actions=actions,
                                      data=pkt.data)

            datapath.send_msg(out)

        else:
            # TODO - handle non HTTP packets here. Whatever you want to do with them.
            logging.info("Received a non HTTP packet. Dropping it")


class RyuRest(RyuController, RestStatsApi):
    """
    Overview is here: https://osrg.github.io/ryu-book/en/html/rest_api.html

    This class extends the RyuController class above in order to add a REST API functionality.

    """

    # A dictionary to specify contexts which this Ryu application wants to use. Its key is a name of context and its
    # value is an ordinary class which implements the context. The class is instantiated by app_manager and the instance
    # is shared among RyuApp subclasses which has _CONTEXTS member with the same key. A RyuApp subclass can obtain a
    # reference to the instance via its __init__'s kwargs as the following.
    # Class variable _CONTEXT is used to specify Ryu’s WSGI-compatible Web server class. By doing so, WSGI’s Web server
    # instance can be acquired by a key called the wsgi key.
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'dpset': dpset.DPSet
    }

    def __init__(self, *args, **kwargs):
        self.switches = {}
        wsgi = kwargs['wsgi']

        # For registration, the register method is used. When executing the register method, the dictionary object is
        # passed in the key name ryu_app so that the constructor of the controller can access the instance
        # of the RyuRest class.
        wsgi.register(RyuRestServer, {ryu_instance: self})
        RyuController.__init__(self, *args, **kwargs)
        RestStatsApi.__init__(self, *args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Parent class switch_features_handler is overridden. This method, upon rising of the SwitchFeatures event,
        acquires the datapath object stored in event object ev and stores it in instance variable switches. Also, at
        this time, an empty dictionary is set as the initial value in the MAC address table.

        :param ev: The switch event object containing the message data For this function we expect an instance of
                   ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
        :return:
        """

        super(RyuRest, self).switch_features_handler(ev)  # Call the original switch features method
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

    def get_datapath(self, dpid: int) -> Datapath:
        """
        Allows you to retrieve the Datapath for a switch with the associated DPID

        :param dpid: The dpid you want to retrieve.
        :return: a Datapath object representing the given switch or None if it is not found.
        """

        return self.switches.get(dpid, None)


class RyuRestServer(StatsController):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'dpset': dpset.DPSet
    }

    def __init__(self, req, link, data, **config):
        data["dpset"] = data[ryu_instance].dpset

        # waiters in this case is ultimately used by ofctl_utils.py. It appears to be used for locks
        data["waiters"] = {}
        super(RyuRestServer, self).__init__(req, link, data, **config)
        self.ryu_app = data[ryu_instance]

    # I used half a bracket on path. If you add the other half it breaks. Did I just accidentally hack webobs?
    # It probably shouldn't work like this.
    @route('/ryu_app', '/ryu_app/ryuapi/{path', methods=['GET', 'PUT'])
    def ryuapi(self, req: json, **kwargs) -> Response:

        http = urllib3.PoolManager()

        response = http.request('GET', 'http://127.0.0.1:8080/' + kwargs["path"])

        return Response(content_type='application/json', text=response.body)

    @route('/ryu_app', '/ryu_app/getports/{dpid}', methods=['GET'])
    def getports(self, req: json, **kwargs) -> Response:
        """
        Get a listing of all the OpenFlow port ID / switch port name combinations.

        Example request: curl -X GET -d http://127.0.0.1:8080/ryu_app/getports/150013889525632

        :param req: Used to generate the appropriate CORs headers, but otherwise unused in this function.
        :param kwargs: Expects an argument called dpid which contains the dpid of the switch you want to modify
        :return: Returns a list of tuples in the form of (<openflow_port_id>: int, <switch_port_name>: string>)
        """

        switch_instance = self.ryu_app
        dpid = int(kwargs['dpid'])

        port_list = []

        for port, port_info in switch_instance.dpset.port_state[dpid].items():
            port_list.append({"hw_addr": port_info.hw_addr, "name": port_info.name.decode("utf-8"), "openflow_port": port})

        # Sort the ports by openflow port order - this corresponds to their order on the switch as well
        port_list = sorted(port_list, key=lambda i: i["openflow_port"])

        body = json.dumps(port_list)

        return create_response(req, body)


def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6633')  # The port on which you want the controller to listen.
    sys.argv.append('main')  # This is the name of the Ryu app
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == '__main__':
    main()
