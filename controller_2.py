from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *
from switch import *
from router import *

log = core.getLogger()
router_interface_dict = {}
router_interface_entry_init(router_interface_dict,122,1, "10.0.0.1","02:00:DE:AD:BE:11")
router_interface_entry_init(router_interface_dict,122,2, "20.0.0.1","02:00:DE:AD:BE:12")
router_interface_entry_init(router_interface_dict,122,3, "30.0.0.1","02:00:DE:AD:BE:13")
routing_table_dict = {}
router_table_entry_init(routing_table_dict,122,"10.0.0.0/24","0.0.0.0",1)
router_table_entry_init(routing_table_dict,122,"20.0.0.0/24","0.0.0.0",2)
router_table_entry_init(routing_table_dict,122,"30.0.0.0/24","0.0.0.0",3)
class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    global router_interface_dict
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection
    self.init_dict = {}
    self.init_dict = {} 
    if(connection.dpid>=90):
        self.init_dict['router_interface_table'] = {}
	self.init_dict['router_interface_table'] = router_interface_dict[connection.dpid]
        self.init_dict['routing_table'] = {}
	self.init_dict['routing_table'] = routing_table_dict[connection.dpid]
        self.init_dict['arp_table'] = {} 
        self.init_dict['outstanding_arp_req'] = []
        self.init_dict['queue_table'] = {} 

    else:
        self.init_dict['table'] = {} 
        self.init_dict['init'] = {}
    # This binds our PacketIn event listener
    connection.addListeners(self)
    """
    
    In scenario 3, there are many routers and switches. You need to classify a device as a router or a switch based on its DPID
    Remember one thing very carefully. The DPID gets assigned based on how you define tour devices in the topology file.
    So, be careful and DPID here should be coordinated with your definition in topology file.
    For the details of port info table, routing table, of different routers look into the project description document provided.
    Initialize any other data structures you wish to for the routers and switches here

    A word of caution:
    Your router and switch code should be the same for all scenarios. So, be careful to design your data structures for router
    and switches in such a way that your single piece of switch code and router code along with your data structure design
    should work for all the scenarios
    """

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)
    
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    if(event.dpid>=90):
        router_handler(self,packet,packet_in)
    else:
        switch_handler(self,packet,packet_in)
    """
    
    You need to classify a device as either switch or router based on its DPID received in the connection object during
    initialization in __init__ function in tutorial class. Based on the device type you need to call the respective function
    Here is the pseudo code to write

    if packet received from device type is switch:
      invoke switch_handler and pass the object (i.e., self) and the packet and packet_in
    else: (if it is not switch, it means router. We have only two kinds of devices, one is switch and one is router)
      invoke router_handler and pass the object (i.e., self) and the packet and packet_in
    """


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    #log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
