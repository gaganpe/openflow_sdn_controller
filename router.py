"""

Your router code and any other helper functions related to router should be written in this file
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *

log = core.getLogger()

"""

  Function : router_handler
  Input Parameters:
      rt_object : The router object. This will be initialized in the controller file corresponding to the scenario in __init__
                  function of tutorial class. Any data structures you would like to use for a router should be initialized
                  in the contoller file corresponding to the scenario.
      packet    : The packet that is received from the packet forwarding switch.
      packet_in : The packet_in object that is received from the packet forwarding switch
"""

def router_handler(rt_object, packet, packet_in):
    match = of.ofp_match.from_packet(packet)
    if (match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST):
        arp_req_handler(rt_object,packet,packet_in)
    if (match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REPLY) :
        arp_reply_handler(rt_object,packet,packet_in)
    router_ip_list = []
    for key,value in (rt_object.init_dict['router_interface_table'].items()):
       router_ip_list.append(str(value['router_ip'])) 
	
    if ((match.dl_type == packet.IP_TYPE ) and (str(match.nw_dst)in router_ip_list)and packet.find('icmp')):
        icmp_req_handler(rt_object,packet,packet_in)
    if (match.dl_type == packet.IP_TYPE ) :
        packet_forward_handler(rt_object,packet,packet_in)
    return 
    


def router_interface_entry_init(router_interface_dict,dpid,port,router_ip,mac_add):
    if(router_interface_dict.get(dpid) == None):
        router_interface_dict[dpid] = {}
    router_interface_dict[dpid][port] = {}
    router_interface_dict[dpid][port]['router_ip'] = IPAddr(router_ip)
    router_interface_dict[dpid][port]['mac_add'] = EthAddr(mac_add)
    router_interface_dict[dpid][port]['rule'] = 0


def icmp_req_handler(rt_object,packet,packet_in):
    icmp_ = icmp()
    icmp_.type =TYPE_ECHO_REPLY
    icmp_.payload = packet.find("icmp").payload

    # Make the IP packet around it
    ipp = ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    ipp.srcip = packet.find("ipv4").dstip
    ipp.dstip = packet.find("ipv4").srcip

    # Ethernet around that...
    e = ethernet()
    e.src = packet.dst
    e.dst = packet.src
    e.type = e.IP_TYPE

    # Hook them up...
    ipp.payload = icmp_
    e.payload = ipp
    rt_object.resend_packet(e,packet_in.in_port)

def icmp_unreach_handler(rt_object,packet,packet_in):
    icmp_ = icmp()

    rt_ip = rt_object.init_dict['router_interface_table'][packet_in.in_port]['router_ip']

    icmp_.type = TYPE_DEST_UNREACH
    icmp_.code =CODE_UNREACH_HOST
    orig_ip = packet.find('ipv4')
    d = orig_ip.pack()
    d = d[:orig_ip.hl * 4 + 8]
    import struct
    d = struct.pack("!HH", 0,0) + d 
    icmp_.payload = d
    ipp = ipv4()
    ipp.payload = icmp_ 
    ipp.protocol = ipp.ICMP_PROTOCOL
    ipp.srcip = rt_ip
    ipp.dstip = packet.find("ipv4").srcip

    # Ethernet around that...
    e = ethernet()
    e.src = packet.dst
    e.dst = packet.src
    e.type = e.IP_TYPE

    # Hook them up...
    e.payload = ipp
    rt_object.resend_packet(e,packet_in.in_port)

def router_table_entry_init(routing_table_dict,dpid,network_add,next_hop,port,default = False):
    if(routing_table_dict.get(dpid) == None):
        routing_table_dict[dpid] = []
    new_dict = {}
    new_dict['nw_add'] = (IPAddr(network_add.split("/")[0]),int(network_add.split("/")[1]))
    new_dict['next_hop'] = IPAddr(next_hop)
    new_dict['port'] = port
    new_dict['default'] = default
    routing_table_dict[dpid].append(new_dict)

def arp_req_handler(rt_object,packet,packet_in):
        match = of.ofp_match.from_packet(packet)
        rt_object.init_dict['arp_table'][packet.payload.protosrc] = packet.src
        if (str(match.nw_dst) != str(rt_object.init_dict['router_interface_table'][packet_in.in_port]['router_ip'])):
            return
        if rt_object.init_dict['router_interface_table'][packet_in.in_port]['rule'] == 0:
            msg = of.ofp_flow_mod()
            msg.match.in_port = packet_in.in_port
            msg.match.dl_type = packet.ARP_TYPE 
            msg.match.nw_dst = rt_object.init_dict['router_interface_table'][packet_in.in_port]['router_ip']
            msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
            rt_object.connection.send(msg)
            rt_object.init_dict['router_interface_table'][packet_in.in_port]['rule'] == 1
        r = arp(opcode=arp.REPLY,hwsrc=rt_object.init_dict['router_interface_table'][packet_in.in_port]['mac_add'],hwdst=match.dl_src,protosrc = rt_object.init_dict['router_interface_table'][packet_in.in_port]['router_ip'],protodst = match.nw_src)
        e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst,payload = r)
	rt_object.resend_packet(e,packet_in.in_port)


def arp_reply_handler(rt_object,packet,packet_in):
        rt_object.init_dict['arp_table'][packet.payload.protosrc] = packet.src
	if packet.payload.protosrc in rt_object.init_dict['outstanding_arp_req'] :rt_object.init_dict['outstanding_arp_req'].remove(packet.payload.protosrc)
	if(rt_object.init_dict['queue_table'].get(packet.payload.protosrc)!= None):
		for queued_packet in rt_object.init_dict['queue_table'].get(packet.payload.protosrc):		
			msg = of.ofp_flow_mod()
			msg.match.dl_type = packet.IP_TYPE 
			msg.match.nw_dst = packet.payload.protosrc
			msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
			msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
			msg.actions.append(of.ofp_action_output(port = queued_packet['op_port']))
			rt_object.connection.send(msg)
        		e = ethernet(type=packet.IP_TYPE, src=packet.dst, dst=packet.src,payload = queued_packet['packet'].payload)
			rt_object.resend_packet(e,queued_packet['op_port'])
    		rt_object.init_dict['queue_table'][packet.payload.protosrc] = []
        if(rt_object.init_dict.get('server_table') !=None):
                if rt_object.init_dict['server_table'].get(str(packet.payload.protosrc)) != None:
                    if rt_object.init_dict['server_table'][str(packet.payload.protosrc)]['switch_delete'] == 0:
			from controller_3b import server_mac_recvd
                        server_mac_recvd(rt_object,packet.payload.protosrc,packet)

def arp_req_generator(rt_object,hw_src,nw_src,next_hop_ip,op_port):
	if(next_hop_ip not in rt_object.init_dict['outstanding_arp_req']):
		r = arp(opcode=arp.REQUEST,hwsrc=hw_src,hwdst=ETHER_BROADCAST,protosrc = nw_src,protodst = next_hop_ip)
		e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst,payload = r)
		rt_object.resend_packet(e,op_port)
		rt_object.init_dict['outstanding_arp_req'].append(next_hop_ip)		
def packet_forward_handler(rt_object,packet,packet_in):
	match = of.ofp_match.from_packet(packet)
	default_pos = -1
	i=0
	for rt_table_ent in rt_object.init_dict['routing_table']:		
		if(rt_table_ent['default']):
			default_pos = i
			continue
		if(prefix_match(match.get_nw_dst(),rt_table_ent['nw_add'])):		
			next_hop_ip = ''
			next_hop_rt=0
			if(str(rt_table_ent['next_hop']) == "0.0.0.0"):
				next_hop_ip = packet.payload.dstip
			else:
				next_hop_ip = rt_table_ent['next_hop']
				next_hop_rt=1
			next_hop_hw_addr = rt_object.init_dict['arp_table'].get(next_hop_ip)
	 		add_rule(rt_object,packet,packet_in,rt_table_ent,next_hop_ip,next_hop_hw_addr,next_hop_rt)
			return
		i+=1
	if(default_pos!= -1):
		rt_table_ent = rt_object.init_dict['routing_table'][default_pos]
		next_hop_ip = rt_table_ent['next_hop']
		next_hop_hw_addr = rt_object.init_dict['arp_table'].get(next_hop_ip)
	 	add_rule(rt_object,packet,packet_in,rt_table_ent,next_hop_ip,next_hop_hw_addr,0)
		return
		
	icmp_unreach_handler(rt_object,packet,packet_in)

def cidr_str(nw_address):
	return (str(nw_address[0]) + "/" + str(nw_address[1]))

def prefix_match(match_src,match_dst):
    dst_ip = str(match_dst[0])
    dst_ip_digits_list_str = dst_ip.split(".")
    dst_ip_digits_list = [int(x) for x in dst_ip_digits_list_str]
    dst_ip_int = (dst_ip_digits_list[0]<<24) + (dst_ip_digits_list[1]<<16) + (dst_ip_digits_list[2]<<8)+ (dst_ip_digits_list[3])
    dst_cidr = match_dst[1]
    dst_sm = int('1'*dst_cidr,2)<<(32 - dst_cidr)
    dst_nw_val = dst_ip_int & dst_sm
    src_ip = str(match_src[0])
    src_ip_digits_list_str = src_ip.split(".")
    src_ip_digits_list = [int(x) for x in src_ip_digits_list_str]
    src_ip_int = (src_ip_digits_list[0]<<24) + (src_ip_digits_list[1]<<16) + (src_ip_digits_list[2]<<8) + (src_ip_digits_list[3])
    src_nw_val = src_ip_int & dst_sm
    return src_nw_val == dst_nw_val


def add_rule(rt_object,packet,packet_in,rt_table_ent,next_hop_ip,next_hop_hw_addr,next_hop_rt):
	if(next_hop_hw_addr == None):
		new_dict = {}
		new_dict['packet_in'] = packet_in
		new_dict['packet'] = packet
		new_dict['nw_add'] = rt_table_ent['nw_add']
		new_dict['op_port'] = rt_table_ent['port']
		ip_queue = rt_object.init_dict['queue_table'].get(next_hop_ip)
		if(ip_queue == None):
			rt_object.init_dict['queue_table'][next_hop_ip] = []
		rt_object.init_dict['queue_table'][next_hop_ip].append(new_dict)
		hw_src = rt_object.init_dict['router_interface_table'][rt_table_ent['port']]['mac_add']
		nw_src = rt_object.init_dict['router_interface_table'][rt_table_ent['port']]['router_ip']
		arp_req_generator(rt_object,hw_src,nw_src,next_hop_ip,rt_table_ent['port'])
	else:
		msg = of.ofp_flow_mod()
		msg.match.dl_type = packet.IP_TYPE 
		if(next_hop_rt == None):
			msg.match.nw_dst = cidr_str(rt_table_ent['nw_add'])
		else:
			msg.match.nw_dst = packet.payload.dstip
		msg.actions.append(of.ofp_action_dl_addr.set_dst(next_hop_hw_addr))
		src_hw_addr = rt_object.init_dict['router_interface_table'][rt_table_ent['port']]['mac_add']
		msg.actions.append(of.ofp_action_dl_addr.set_src(src_hw_addr))
		msg.actions.append(of.ofp_action_output(port = rt_table_ent['port']))
		rt_object.connection.send(msg)
       		e = ethernet(type=packet.IP_TYPE, src=src_hw_addr, dst=next_hop_hw_addr,payload = packet.payload)
		rt_object.resend_packet(e,rt_table_ent['port'])
	return
