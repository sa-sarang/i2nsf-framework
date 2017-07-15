#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
from functools import partial
from time import sleep
from mininet.cli import CLI
from mininet.link import Intf
from mininet.link import Link
from mininet.log import setLogLevel, info

import os

class SingleSwitchTopo(Topo):
	"Single switch connected to n hosts."
	def build(self, n=2):
		switch_1 = self.addSwitch('switch1');
		switch_2 = self.addSwitch('switch2');
		switch_3 = self.addSwitch('switch3');
		switch_4 = self.addSwitch('switch4');



######################################### SFF ####################################
		sff1 = self.addHost('sff1', ip='10.0.0.100');
		self.addLink(sff1, switch_2);
	  
 
#################################### NSFs #########################################
		firewall = self.addHost('firewall', ip='10.0.0.200');
		self.addLink(firewall, switch_1);

		dpi = self.addHost('dpi', ip='10.0.0.201');
		self.addLink(dpi, switch_1);


		admin = self.addHost('admin', ip='10.0.0.101');
		self.addLink(admin, switch_1);


############################## Eployee according to postion ########################
		staff_1 = self.addHost('staff_1', ip='10.0.0.2');
		self.addLink(staff_1, switch_4);

		staff_2 = self.addHost('staff_2', ip='10.0.0.3');
		self.addLink(staff_2, switch_4);

		manager = self.addHost('manager', ip='10.0.0.14');
		self.addLink(manager, switch_4);

		president = self.addHost('president', ip='10.0.0.24');
		self.addLink(president, switch_4);



############################ Internet #########################################
		nat = self.addNode('nat', ip = '10.0.0.150', inNamespace = False);
		self.addLink(nat, switch_3);

		
#############################Link Connection##########################
		self.addLink(switch_1, switch_2);
		self.addLink(switch_2, switch_3);
		self.addLink(switch_2, switch_4);
		self.addLink(switch_1, switch_3);
		

def fixNetworkManager( root, intf ):
	 """Prevent network-manager from messing with our interface,
		by specifying manual configuration in /etc/network/interfaces
		root: a node in the root namespace (for running commands)
		intf: interface name"""
	 cfile = '/etc/network/interfaces'
	 line = '\niface %s inet manual\n' % intf
	 config = open( cfile ).read()
	 if line not in config:
		 print '*** Adding', line.strip(), 'to', cfile
		 with open( cfile, 'a' ) as f:
			  f.write( line )
		 # Probably need to restart network-manager to be safe -
		 # hopefully this won't disconnect you
		 root.cmd( 'sudo service network-manager restart' )


def simpleTest():

	os.system("sudo mysql -u root -p mysql < ./schema.sql")
	"Create and test a simple network"
	topo = SingleSwitchTopo(n=4)
	net = Mininet(topo, controller=partial(RemoteController, ip='127.0.0.1', port=6633))
	net.start();
	os.system("sudo ./sendFlowRuleForBasicPacket.sh PUT 127.0.0.1:8181")
	os.system("sudo ./sendFlowRuleForBasicPacket.sh DELETE 127.0.0.1:8181")
	net.pingAll();
	os.system("sudo ./sendFlowRuleForBasicPacket.sh PUT 127.0.0.1:8181")



	# Inintalize components
	nat = net.get('nat');
	sff = net.get('sff1');
	firewall = net.get('firewall');
	admin = net.get('admin');
	staff_1 = net.get('staff_1');
	staff_2 = net.get('staff_2');
	manager = net.get('manager');
	president = net.get('president');

	os.system("sudo cp ~/suricata-3.2.1/suricata.yaml /etc/suricata/suricata.yaml");

	firewall.cmd('cd ../NSF/Firewall; sudo make init');
	firewall.cmd('secu');
	firewall.cmd('sudo ../../bin/firewall >> /tmp/firewall.out &');

        admin.cmd('cd ../RESTCONF');
        admin.cmd('sudo npm start >> /tmp/webserver1.out &');
	admin.cmd('cd ../SecurityController');
	admin.cmd('sudo service apache2 stop >> /tmp/webserver.out');
	admin.cmd('sudo service apache2 start >> /tmp/webserver.out');
	admin.cmd('sudo python server.py >> /tmp/webserver.out &');


	staff_1.cmd( 'sudo route add default gw', '10.0.0.100')
	staff_2.cmd( 'sudo route add default gw', '10.0.0.100')
	manager.cmd( 'sudo route add default gw', '10.0.0.100')
	president.cmd( 'sudo route add default gw', '10.0.0.100')

	sff.cmd( 'sudo route add default gw', '10.0.0.200')
	sff.cmd( 'sudo sysctl net.ipv4.ip_forward=1')

	firewall.cmd( 'sudo route add default gw', '10.0.0.150')
	firewall.cmd( 'sudo sysctl net.ipv4.ip_forward=1')
	firewall.cmd( 'sudo iptables -I FORWARD -j NFQUEUE')

	firewall.cmd('sudo rm /var/run/suricata.pid >> /tmp/firewall.out');
	firewall.cmd('sudo /usr/bin/suricata -D -c /etc/suricata/suricata.yaml -q 0 >> /tmp/firewall.out');
	firewall.cmd('sudo /usr/bin/suricatasc -c reload-rules & >> /tmp/firewall.out');


	# Identify the interface connecting to the mininet network
	localIntf = nat.defaultIntf()
	fixNetworkManager(nat, 'nat-eth0')

	# Flush any currently active rules
	nat.cmd( 'sudo iptables -F' )
	nat.cmd( 'sudo iptables -t nat -F' )

	# Create default entries for unmatched traffic
	nat.cmd( 'sudo iptables -P INPUT ACCEPT' )
	nat.cmd( 'sudo iptables -P OUTPUT ACCEPT' )
	nat.cmd( 'sudo iptables -P FORWARD DROP' )

	# Configure NAT
	nat.cmd( 'sudo iptables -I FORWARD -i', localIntf, '-d', '10.0/8', '-j DROP' )
	nat.cmd( 'sudo iptables -A FORWARD -i', localIntf, '-s', '10.0/8', '-j ACCEPT' )
	nat.cmd( 'sudo iptables -A FORWARD -i', 'eth0', '-d', '10.0/8', '-j ACCEPT' )
	nat.cmd( 'sudo iptables -t nat -A POSTROUTING -o ', 'eth0', '-j MASQUERADE' )

	# Instruct the kernel to perform forwarding
	nat.cmd( 'sudo sysctl net.ipv4.ip_forward=1' )
			
	CLI(net)


	#Kill Suricata
	os.system("sudo ps -ef | grep /etc/suricata/suricata.yaml | grep -v grep >> temp.txt")
	fin=open('temp.txt','r')
	line=fin.read()
	temp=line.split('      ')
	pid=temp[1].split()
	fin.close()
	os.system("sudo kill -9 "+pid[0])
	os.system("rm temp.txt")


	"""Stop NAT/forwarding between Mininet and external network"""
	# Flush any currently active rules
	nat.cmd( 'sudo iptables -F' )
	nat.cmd( 'sudo iptables -t nat -F' )

	# Instruct the kernel to stop forwarding
	nat.cmd( 'sudo sysctl net.ipv4.ip_forward=0' )

	os.system("sudo ./sendFlowRuleForBasicPacket.sh DELETE 127.0.0.1:8181")


	net.stop()
	
if __name__ == '__main__':
	"Tell mininet to print useful information"
	setLogLevel('info')
	simpleTest()
	os.system("sudo mn -c");


