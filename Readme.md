# SDN Controller Design

In this project an SDN controller is desigend to operate as a switch and and router.\ We test the routers and switches in small custom networks to test the capabilities of the routers including support for ARP, ICMP and IP packets. Firewall capabilites are also tested. The testing is performed in a Mininet VM with MobaXTerm for SSH connection. Mininet VM can be downloaded from this [link](https://github.com/mininet/mininet/releases/). The communication setup information is present [here](https://github.com/mininet/openflow-tutorial/wiki/Set-up-Virtual-Machine) . 

Authors: Gagan Punathil Ellath, Simran Saxena and Yude Wei.

## Router
The router has the following capabilites:
- Reply to ARP packets destined to the interfaces in the router
- Drop ARP packets not destined to the router
- Longest Prefix matching based routing support
- ARP query if the MAC address is not known
- Buffering packets for which the MAC destination is not known, use ARP to obtain the MAC and then queue all the packets to the destination
- Default Routes support
- Rules Installation: There should be rules present for each of the IP packets to be routed
- ICMP Echo reply for ping requests to the router interfaces
- ICMP network unreachable if the the route to the destination is not known
## Switch
The switch has the following capabilites:
- Layer 2 capabilities
- Broadcast frames with unknown MAC addresses to all ports and frames with broadcast MAC addresses
- Self Learning: When the MAC address of a device connected to a port is obtained, a new openflow rule has to be installed for the port to MAC mapping

## Scenarios
Each of the scenarios contain different network topologies which are described below.\
**Scenario 1**:\
Layer 2 switch with 3 hosts connected to it. A single network.\
**Scenario 2**:\
Router with 3 hosts connected to it. 3 different networks.\
**Scenario 3**:\
THis is the closest to a real world network. 15 Hosts, 5 switches 3 routers.
 Each switch is connected to 3 hosts. One of the switches is connected to one router, each of the other routers are connected to two switches each (and in turn they are connected to 3 hosts each). The routers are in a triangular connection except two of the routers are not connected.\
**Scenario 3b**:\
Same topology as scenario 3, communication to one of the hosts is blocked, and one of the hosts is treated as a secure server allowing packets only from specific hosts and blocking all other communications 
## Usage
Place the controllller files in the _/home/mininet /pox/pox/misc/_ folder along with the router.py and switch.py files. The topology files are placed in the _/home/mininet/mininet/custom/_ folder.\
For each of the scenarios we start the controller and setup the topology using the following commands:\
**Scenario 1**:
```bash
./pox.py log.level --DEBUG misc.controller_1
sudo mn --custom topology_1.py --topo mytopo --mac --controller remote
```
**Scenario 2**:
```bash
./pox.py log.level --DEBUG misc.controller_2
sudo mn --custom topology_2.py --topo mytopo --mac --controller remote
```
**Scenario 3**:
```bash
./pox.py log.level --DEBUG misc.controller_3
sudo mn --custom topology_3.py --topo mytopo --mac --controller remote
```
**Scenario 3b**:
```bash
./pox.py log.level --DEBUG misc.controller_3b
sudo mn --custom topology_3.py --topo mytopo --mac --controller remote
```
The connections can be tested in the mininet command prompt which is opened after execution of the above commands.\
**Scenario 1**:
```bash
# ping 
pingall
h1 ping h2
# test tcp throughput
iperf h1 h2
```
In a bash shell we can test the openflow rules installation on the switch using:
```bash
sudo ovs-ofctl dump-flows s1
```
**Scenario 2**:
```bash
# ping 
pingall
h1 ping h2
# ping router interfaces 
h1 ping 30.0.0.1 
h1 ping 10.0.0.1
# ping unreachable address
h1 ping 8.8.8.8
# test tcp throughput
iperf h1 h2
```
**Scenario 3**:
```bash
# ping
h9 ping h10
h9 ping h12
h9 ping h21
pingall
# ping router interfaces
h9 ping 172.17.16.1
h9 ping 20.0.0.1
h9 ping 20.0.0.129
# ping unreachable address
h9 ping 8.8.8.8
h21 ping 8.8.8.8
# test tcp throughput
iperf h9 h12
iperf h9 h21
```
**Scenario 3b**:
```bash
# ping blocked for h12
h9 ping h12
h12 ping h14
pingall
# No TCP throughput for h12
iperf h16 h12
# h17 server test - Ping only from h9
h9 ping h17
h17 ping h17
#TCP communication only from h18
iperf h18 h17
iperf h7 h17
```