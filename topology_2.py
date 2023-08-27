"""
Three devices on different networks and all connected by a single router

	host --- router ---- host
		   		|
		   		|
		   		|
		  	   host

"""

from mininet.topo import Topo

class MyTopo(Topo):
    "Topology for scenario2"

    def __init__(self):
	"Create custom topology."

	#Initialize the topology
	Topo.__init__(self)
	
	h1= self.addHost("h1", ip = "10.0.0.2/24", defaultRoute= "via 10.0.0.1")
	h2= self.addHost("h2", ip = "20.0.0.2/24", defaultRoute= "via 20.0.0.1")
	h3= self.addHost("h3", ip = "30.0.0.2/24", defaultRoute= "via 30.0.0.1")


	r1= self.addSwitch ("r1", dpid= "000000000000007A")

	self.addLink(h1,r1,None,1)
	self.addLink(h2,r1,None,2)
	self.addLink(h3,r1,None,3)


topos = { 'mytopo':(lambda:MyTopo())}
