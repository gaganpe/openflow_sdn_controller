"""

Your switch code and any other helper functions related to switch should be written in this file
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *

log = core.getLogger()
all_ports = of.OFPP_ALL
"""

  Function : switch_handler
  Input Parameters:
      sw_object : The switch object. This will be initialized in the controller file corresponding to the scenario in __init__
                  function of tutorial class. Any data structures you would like to use for a switch should be initialized
                  in the contoller file corresponding to the scenario.
      packet    : The packet that is received from the packet forwarding switch.
      packet_in : The packet_in object that is received from the packet forwarding switch
"""
def switch_handler(sw_object, packet, packet_in):
	init_done = sw_object.init_dict['init'].get(packet_in.in_port)
	if init_done == None:
	    msg = of.ofp_flow_mod()
	    msg.match.dl_dst = EthAddr("FF:FF:FF:FF:FF:FF") 
	    msg.match.in_port = packet_in.in_port
	    msg.actions.append(of.ofp_action_output(port = all_ports))
            sw_object.connection.send(msg)
	    sw_object.init_dict['init'][packet_in.in_port] = 1
	sw_object.init_dict['table'][packet.src] =packet_in.in_port 
	dst_port = sw_object.init_dict['table'].get(packet.dst) 
	if dst_port == None:
	    sw_object.resend_packet(packet_in,all_ports)
	else:
            # This is the packet that just came in -- we want to
	    # install the rule and also resend the packet.
    	    msg = of.ofp_flow_mod()
            msg.match.in_port = packet_in.in_port
            msg.match.dl_dst = packet.dst
            msg.actions.append(of.ofp_action_output(port = dst_port))
            sw_object.connection.send(msg)
    	    msg = of.ofp_flow_mod()
            msg.match.in_port = dst_port
            msg.match.dl_dst = packet.src
            msg.actions.append(of.ofp_action_output(port = packet_in.in_port))
            sw_object.connection.send(msg)
	    sw_object.resend_packet(packet_in,dst_port)
	return 
