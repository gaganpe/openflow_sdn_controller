
"""

This is the controller file corresponding to scenario 3.
"""

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
router_interface_entry_init(router_interface_dict,90,1, "172.17.16.1","02:00:DE:AD:BE:11")
router_interface_entry_init(router_interface_dict,90,2, "192.168.0.1","02:00:DE:AD:BE:12")
router_interface_entry_init(router_interface_dict,90,3, "192.168.0.5","02:00:DE:AD:BE:13")
router_interface_entry_init(router_interface_dict,91,1, "10.0.0.1","02:00:DE:AD:BE:21")
router_interface_entry_init(router_interface_dict,91,2, "10.0.0.129","02:00:DE:AD:BE:22")
router_interface_entry_init(router_interface_dict,91,3, "192.168.0.2","02:00:DE:AD:BE:23")
router_interface_entry_init(router_interface_dict,92,1, "20.0.0.1","02:00:DE:AD:BE:31")
router_interface_entry_init(router_interface_dict,92,2, "20.0.0.129","02:00:DE:AD:BE:32")
router_interface_entry_init(router_interface_dict,92,3, "192.168.0.6","02:00:DE:AD:BE:33")
routing_table_dict = {}
router_table_entry_init(routing_table_dict,90,"172.17.16.0/24","0.0.0.0",1)
router_table_entry_init(routing_table_dict,90,"10.0.0.0/24","192.168.0.2",2)
router_table_entry_init(routing_table_dict,90,"20.0.0.0/24","192.168.0.6",3)
router_table_entry_init(routing_table_dict,91,"10.0.0.0/25","0.0.0.0",1)
router_table_entry_init(routing_table_dict,91,"10.0.0.128/25","0.0.0.0",2)
router_table_entry_init(routing_table_dict,91,"172.17.16.0/24","192.168.0.1",3)
router_table_entry_init(routing_table_dict,91,"0.0.0.0/0","192.168.0.1",3,True)
router_table_entry_init(routing_table_dict,92,"20.0.0.0/25","0.0.0.0",1)
router_table_entry_init(routing_table_dict,92,"20.0.0.128/25","0.0.0.0",2)
router_table_entry_init(routing_table_dict,92,"10.0.0.0/24","192.168.0.5",3)
router_table_entry_init(routing_table_dict,92,"172.17.16.0/24","192.168.0.5",3)
block_table = []
server_table = {}
global_router_server_dict = {}
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
    if(connection.dpid>=90):
        self.init_dict['router_interface_table'] = {}
	self.init_dict['router_interface_table'] = router_interface_dict[connection.dpid]
        self.init_dict['routing_table'] = {}
	self.init_dict['routing_table'] = routing_table_dict[connection.dpid]
	self.init_dict['server_table'] = server_table
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
    if firewall_cap(self,packet,packet_in):
        if(event.dpid>=90):
            router_handler(self,packet,packet_in)
        else:
            switch_handler(self,packet,packet_in)
    """
    
    You need to classify a device as either switch or router based on its DPID received in the connection object during
    initialization in __init__ function in tutorial class. Based on the device type you need to call the respective function
witch_server_port   Here is the pseudo code to write

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




def block_table_entry(switch_dpid,switch_rt_port,switch_block_port,block_ip):
    global block_table
    new_dict = {}
    new_dict['switch_dpid'] = switch_dpid
    new_dict['block_ip'] = IPAddr(block_ip)
    new_dict['switch_rt_port'] = switch_rt_port
    new_dict['switch_block_port'] = switch_block_port
    new_dict['switch_init'] = 0
    block_table.append(new_dict)

def server_table_entry(switch_dpid,router_dpid,ping_allow_list,tcp_allow_list,switch_server_port,server_ip):
    global server_table
    new_dict = {}
    new_dict['switch_dpid'] = switch_dpid
    new_dict['router_dpid'] = router_dpid
    new_dict['server_ip'] = IPAddr(server_ip)
    new_dict['ping_allow_list'] = ping_allow_list
    new_dict['switch_server_port'] = switch_server_port
    new_dict['ping_allow_list'] = [IPAddr(x) for x in ping_allow_list]
    new_dict['tcp_allow_list'] = [IPAddr(x) for x in tcp_allow_list]
    new_dict['switch_init'] = 0
    new_dict['router_init'] = 0
    new_dict['switch_delete'] = 0
    global_router_server_dict[router_dpid] = {}
    global_router_server_dict[router_dpid]['server_ip'] = server_ip
    global_router_server_dict[router_dpid]['allowed_ip'] = ping_allow_list + tcp_allow_list
    server_table[server_ip] = new_dict

block_table_entry(5,4,1,"10.0.0.2")
ping_allow_list = ["172.17.16.2","172.17.16.3","172.17.16.4"]
tcp_allow_list = ["20.0.0.2"]
server_table_entry(6,91,ping_allow_list,tcp_allow_list,3,"10.0.0.132")



def firewall_cap(control_obj,packet,packet_in):
        if block_table != None:
            for entry in block_table:
                if(entry['switch_dpid'] == control_obj.connection.dpid and (entry['switch_init']!=1)):
		    #Routing all packets from blocked ports
                    msg_block = of.ofp_flow_mod()
                    msg_block.priority = 0x8001
                    msg_block.match.in_port = entry['switch_block_port']
                    msg_block.match.dl_type = 0x800
                    control_obj.connection.send(msg_block)
                    entry['switch_init'] = 1
                    of.ofp_port_mod(port_no = entry['switch_block_port'],config = of.OFPPC_NO_FLOOD,mask = of.OFPPC_NO_FLOOD)
                    control_obj.connection.send(msg_block)
                    match = of.ofp_match.from_packet(packet)
                    if(packet_in.in_port == entry['switch_block_port']) :
                        return False
        if server_table != None:
            for key,entry in server_table.items():
                match = of.ofp_match.from_packet(packet)
                if(entry['switch_dpid'] == control_obj.connection.dpid and (entry['switch_init'] != 1)):
                    msg_block = of.ofp_flow_mod()
                    msg_block.priority = 0x8001
                    msg_block.match.in_port = 1
                    msg_block.match.dl_type = 0x800
                    msg_block.match.nw_dst = entry['server_ip']
                    control_obj.connection.send(msg_block)
                    msg_block.match.in_port = 2
                    control_obj.connection.send(msg_block)
                    msg_block = of.ofp_flow_mod()
                    msg_block.match.in_port = 3
                    msg_block.priority = 0x8001
                    msg_block.match.dl_type = 0x800
                    msg_block.match.nw_proto = 1
                    msg_block.match.nw_src = entry['server_ip']
                    msg_block.match.nw_dst = None
                    msg_block.match.tp_src = TYPE_ECHO_REQUEST
                    control_obj.connection.send(msg_block)
                    a=1
                    for i in range(0,len(entry['ping_allow_list'])):
                        msg_block = of.ofp_flow_mod(cookie = a)
                        msg_block.priority = 0x8002
                        msg_block.match.dl_type = 0x800
                        msg_block.match.in_port = 4
                        msg_block.match.nw_proto = 1
                        msg_block.match.nw_dst = entry['server_ip']
                        msg_block.match.nw_src = entry['ping_allow_list'][i]
                        msg_block.match.tp_src = TYPE_ECHO_REQUEST
			msg_block.actions = [of.ofp_action_output(port = 3)]
                        control_obj.connection.send(msg_block)
                        msg_block = of.ofp_flow_mod(cookie = a+1)
                        msg_block.priority = 0x8002
                        msg_block.match.dl_type = 0x800
                        msg_block.match.in_port = 4
                        msg_block.match.nw_proto = 1
                        msg_block.match.nw_src = entry['server_ip']
                        msg_block.match.nw_dst = entry['ping_allow_list'][i]
                        msg_block.match.tp_src = TYPE_ECHO_REQUEST
			msg_block.actions = [of.ofp_action_output(port = 3)]
                        control_obj.connection.send(msg_block)
                        a+=2
                    a=7
                    for i in range(0,len(entry['tcp_allow_list'])):
                        msg_block = of.ofp_flow_mod(cookie = a)
                        msg_block.priority = 0x8002
                        msg_block.match.dl_type = 0x800
                        msg_block.match.in_port = 4
                        msg_block.match.nw_proto = 6
                        msg_block.match.nw_dst = entry['server_ip']
                        msg_block.match.nw_src = entry['tcp_allow_list'][i]
			msg_block.actions = [of.ofp_action_output(port = 3)]
                        control_obj.connection.send(msg_block)
                        msg_block = of.ofp_flow_mod(cookie = a+1)
                        msg_block.priority = 0x8002
                        msg_block.match.dl_type = 0x800
                        msg_block.match.nw_proto = 6
                        msg_block.match.in_port = 2
                        msg_block.match.nw_dst = entry['tcp_allow_list'][i]
                        msg_block.match.nw_src = entry['server_ip']
                        msg_block.actions = [of.ofp_action_output(port = 3)]
                        a+=2 
                        control_obj.connection.send(msg_block)
                    msg_block = of.ofp_flow_mod(cookie = 9)
                    msg_block.priority = 0x8001
                    msg_block.match.dl_type = 0x800
                    msg_block.match.in_port = 4
                    msg_block.match.nw_dst = entry['server_ip']
                    control_obj.connection.send(msg_block)
                    entry['switch_init'] = 1
                if(entry['switch_dpid'] == control_obj.connection.dpid and (entry['switch_delete'] == 1) and (entry['switch_init'] ==1)):
                    for i in range (1,10):
                        msg_block = of.ofp_flow_mod(cookie = i,command = of.OFPFC_DELETE)
                        control_obj.connection.send(msg_block)
                    msg_block = of.ofp_flow_mod()
                    msg_block.priority = 0x8001
                    msg_block.match.in_port = 1
                    msg_block.match.dl_type = 0x800
                    msg_block.match.nw_dst = entry['server_ip']
                    control_obj.connection.send(msg_block)
                    msg_block.match.in_port = 2
                    control_obj.connection.send(msg_block)
                    msg_block = of.ofp_flow_mod()
                    msg_block.match.in_port = 3
                    msg_block.priority = 0x8001
                    msg_block.match.dl_type = 0x800
                    msg_block.match.nw_proto = 1
                    msg_block.match.nw_src = entry['server_ip']
                    msg_block.match.nw_dst = None
                    msg_block.match.tp_src = TYPE_ECHO_REQUEST
                    control_obj.connection.send(msg_block)
                    entry['switch_delete']=2
                ping_allow_list = [str(x) for x in entry['ping_allow_list']]
                tcp_allow_list = [str(x) for x in entry['tcp_allow_list']]
                tcp_found = packet.find('tcp')
                icmp_found = packet.find("icmp")
                if(entry['switch_dpid'] == control_obj.connection.dpid ):
                    if icmp_found and (match.nw_src in ping_allow_list) and match.nw_dst == str(entry['server_ip']) :
                        return True
                    if icmp_found and (match.nw_src not in ping_allow_list) and (match.nw_dst == str(entry['server_ip'])):
                        return False
                    if icmp_found and match.nw_src == str(entry['server_ip']) :
                        if (icmp_found.type == TYPE_ECHO_REQUEST):
                            return False
                        else:
                            return True
                    if tcp_found and match.nw_src == str(entry['server_ip']):
                        if tcp_found.SYN ==1 and tcp_found.ACK == 0:
                            msg_block = of.ofp_flow_mod()
                            msg_block.priority = 0x8002
                            msg_block.idle_timeout = 10
                            msg_block.match.dl_type = 0x800
                            msg_block.match.in_port = packet_in.in_port
                            msg_block.match.nw_proto = 6
                            msg_block.match.nw_dst = match.nw_dst
                            msg_block.match.nw_src = match.nw_src
                            msg_block.match.tp_src = match.tp_src
                            msg_block.match.tp_dst = match.tp_dst
                            control_obj.connection.send(msg_block)
                            return False
                        elif match.nw_dst  not in tcp_allow_list:
                            return False
                        else:
                            msg_block = of.ofp_flow_mod()
                            msg_block.priority = 0x8002
                            msg_block.idle_timeout = 10
                            msg_block.match.dl_type = 0x800
                            msg_block.match.in_port = packet_in.in_port
                            msg_block.match.nw_proto = 6
                            msg_block.match.nw_dst = match.nw_dst
                            msg_block.match.nw_src = match.nw_src
                            msg_block.match.tp_src = match.tp_src
                            msg_block.match.tp_dst = match.tp_dst
                            msg_block.actions = [of.ofp_action_output(port = 3)]
                            control_obj.connection.send(msg_block)
                            control_obj.resend_packet(packet,3)
                            return False
                if (entry['router_dpid'] == control_obj.connection.dpid):
                    if(entry['switch_delete'] == 0):
                        hw_src = router_interface_dict[control_obj.connection.dpid][2]['mac_add']
		        nw_src = router_interface_dict[control_obj.connection.dpid][2]['router_ip']
		        arp_req_generator(control_obj,hw_src,nw_src,entry['server_ip'],2)
                    if icmp_found and (match.nw_src in ping_allow_list) and match.nw_dst == str(entry['server_ip']) :
                        return True
                    if icmp_found and (match.nw_src not in ping_allow_list) and (match.nw_dst == str(entry['server_ip'])):
                        return False
                    if icmp_found and match.nw_src == str(entry['server_ip']) :
                        if (icmp_found.type == TYPE_ECHO_REQUEST):
                            return False
                        else:
                            return True
                    if tcp_found and match.nw_src == str(entry['server_ip']):
                        if tcp_found.SYN ==1 and tcp_found.ACK == 0:
                            msg_block = of.ofp_flow_mod()
                            msg_block.priority = 0x8003
                            msg_block.idle_timeout = 10
                            msg_block.match.dl_type = 0x800
                            msg_block.match.in_port = packet_in.in_port
                            msg_block.match.nw_proto = 6
                            msg_block.match.nw_dst = match.nw_dst
                            msg_block.match.nw_src = match.nw_src
                            msg_block.match.tp_src = match.tp_src
                            msg_block.match.tp_dst = match.tp_dst
                            control_obj.connection.send(msg_block)
                            return False
                        elif match.nw_dst  not in tcp_allow_list:
                            return False
                        else:
                            msg_block = of.ofp_flow_mod()
                            msg_block.priority = 0x8003
                            msg_block.idle_timeout = 10
                            msg_block.match.dl_type = 0x800
                            msg_block.match.in_port = packet_in.in_port
                            msg_block.match.nw_proto = 6
                            msg_block.match.nw_dst = match.nw_dst
                            msg_block.match.nw_src = match.nw_src
                            msg_block.match.tp_src = match.tp_src
                            msg_block.match.tp_dst = match.tp_dst
                            msg_block.actions = [of.ofp_action_output(port = 3)]
                            control_obj.connection.send(msg_block)
                            control_obj.resend_packet(packet,3)
                            return False

	return True
                    



def server_mac_recvd(control_obj,ip,packet):
    ip = str(ip)
    if server_table[ip]['router_init'] == 1:
        return
    entry = server_table[ip]
    msg_block = of.ofp_flow_mod()
    msg_block.priority = 0x8001
    msg_block.match.dl_type = 0x800
    msg_block.match.nw_dst = entry['server_ip']
    control_obj.connection.send(msg_block)
    msg_block = of.ofp_flow_mod()
    msg_block.priority = 0x8001
    msg_block.match.dl_type = 0x800
    msg_block.match.nw_dst = entry['server_ip']
    control_obj.connection.send(msg_block)
    msg_block = of.ofp_flow_mod()
    msg_block.priority = 0x8001
    msg_block.match.dl_type = 0x800
    msg_block.match.nw_src = entry['server_ip']
    control_obj.connection.send(msg_block)
    for ping_entry in entry['ping_allow_list']:
        msg_block = of.ofp_flow_mod()
        msg_block.priority = 0x8002
        msg_block.match.dl_type = 0x800
        msg_block.match.nw_proto = 1
        msg_block.match.in_port = 3
        msg_block.match.nw_src = ping_entry
        msg_block.match.nw_dst = entry['server_ip']
        msg_block.match.tp_src = TYPE_ECHO_REQUEST
	msg_block.actions = [of.ofp_action_dl_addr.set_dst(packet.src)]
        msg_block.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
        msg_block.actions.append(of.ofp_action_output(port = 2))
        control_obj.connection.send(msg_block)
        msg_block = of.ofp_flow_mod()
        msg_block.priority = 0x8002
        msg_block.match.dl_type = 0x800
        msg_block.match.nw_proto = 1
        msg_block.match.in_port = 2
        msg_block.match.nw_dst = ping_entry
        msg_block.match.nw_src = entry['server_ip']
        msg_block.match.tp_src = TYPE_ECHO_REPLY
        msg_block.actions = [of.ofp_action_output(port = 3)]
        control_obj.connection.send(msg_block)
    for tcp_entry in entry['tcp_allow_list']:
        msg_block = of.ofp_flow_mod()
        msg_block.priority = 0x8002
        msg_block.match.dl_type = 0x800
        msg_block.match.nw_proto = 6
        msg_block.match.in_port = 3
        msg_block.match.nw_src = tcp_entry
        msg_block.match.nw_dst = entry['server_ip']
	msg_block.actions = [of.ofp_action_dl_addr.set_dst(packet.src)]
        msg_block.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
        msg_block.actions.append(of.ofp_action_output(port = 2))
        control_obj.connection.send(msg_block)
        msg_block = of.ofp_flow_mod()
        msg_block.priority = 0x8002
        msg_block.match.dl_type = 0x800
        msg_block.match.nw_proto = 6
        msg_block.match.in_port = 2
        msg_block.match.nw_dst = tcp_entry
        msg_block.match.nw_src = entry['server_ip']
        msg_block.actions = [of.ofp_action_output(port = of.OFPP_CONTROLLER)]
        control_obj.connection.send(msg_block)
    entry['switch_delete'] = 1
