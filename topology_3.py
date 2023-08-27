"""
A complex containing 3 routers, 5 switches, 5 subnets and 15 hosts.
"""

from mininet.topo import Topo

class MyTopo(Topo):
    "Simple topology example."
    def __init__(self):
      Topo.__init__(self)
      s4 = self.addSwitch( 's4' )
      for i in range(2,5):
          host = self.addHost( 'h%d'%(i+7), ip='172.17.16.%d/24'%i, defaultRoute='via 172.17.16.1') 
          self.addLink(host,s4,intfName2 = 's4-h%d'%(i+7))
      s5 = self.addSwitch( 's5' )
      for i in range(2,5):
          host = self.addHost( 'h%d'%(i+10), ip='10.0.0.%d/25'%i, defaultRoute='via 10.0.0.1') 
          self.addLink(s5,host,i-1)
      s6 = self.addSwitch( 's6' )
      for i in range(0,3):
          host = self.addHost( 'h%d'%(i+15), ip='10.0.0.%d/25'%(i+130), defaultRoute='via 10.0.0.129') 
          self.addLink(host,s6,intfName2 = 's6-h%d'%(i+15))
      s7 = self.addSwitch( 's7' )
      for i in range(2,5):
          host = self.addHost( 'h%d'%(i+16), ip='20.0.0.%d/25'%i, defaultRoute='via 20.0.0.1') 
          self.addLink(host,s7,intfName2 = 's7-h%d'%(i+16))
      s8 = self.addSwitch( 's8' )
      for i in range(0,3):
          host = self.addHost( 'h%d'%(i+21), ip='20.0.0.%d/25'%(i+130), defaultRoute='via 20.0.0.129') 
          self.addLink(host,s8,intfName2 = 's8-h%d'%(i+21))
      r1 = self.addSwitch( 'r1', dpid = '000000000000005A')
      r2 = self.addSwitch( 'r2', dpid = '000000000000005B')
      r3 = self.addSwitch( 'r3', dpid = '000000000000005C')
      self.addLink(r1,s4,1)
      self.addLink(r2,s5,1,4)
      self.addLink(r2,s6,2)
      self.addLink(r3,s7,1)
      self.addLink(r3,s8,2)
      self.addLink(r1,r2,2,3)
      self.addLink(r1,r3,3,3)

    
 

topos = { 'mytopo':(lambda:MyTopo())}
