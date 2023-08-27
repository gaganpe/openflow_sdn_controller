"""
Three devices on same network and all connected by a switch

	host --- switch ---- host
		   		|
		   		|
		   		|
		  	   host

"""

from mininet.topo import Topo

class scenario1(Topo):
    "Topology for scenario1"

    def __init__(self):
	"Create custom topology."

	#Initialize the topology
	Topo.__init__(self)
	
	h1= self.addHost("h1", ip = "10.0.0.2/24")
	h2= self.addHost("h2", ip = "10.0.0.3/24")
	h3= self.addHost("h3", ip = "10.0.0.4/24")


	s1= self.addSwitch("s1") 

	self.addLink(h1,s1)
	self.addLink(h2,s1)
	self.addLink(h3,s1)

topos = { 'mytopo':(lambda:scenario1())}
