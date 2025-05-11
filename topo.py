from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class DataControlMLTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1') 
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5') 
        s6 = self.addSwitch('s6') 
        s7 = self.addSwitch('s7') 

        subnets = {
            'a': ('10.0.0.1/8', s1),
            'b': ('90.0.0.1/8', s2),
            'c': ('200.0.0.1/8', s3),  
            'd': ('172.0.0.1/8', s4),
            'e': ('250.0.0.1/8', s5)
        }

        for label, (ip, sw) in subnets.items():

        
        for i in range(1, 4):
            h = self.addHost(f's1h{i}', ip=f'10.0.{i}.10/8')
            self.addLink(h, s1)

            h = self.addHost(f's2h{i}', ip=f'90.0.{i}.10/8')
            self.addLink(h, s2)

            h = self.addHost(f's3h{i}', ip=f'200.0.{i}.10/8')
            self.addLink(h, s3)

            h = self.addHost(f's4h{i}', ip=f'172.0.{i}.10/8')
            self.addLink(h, s4)

            h = self.addHost(f's5h{i}', ip=f'250.0.{i}.10/8')
            self.addLink(h, s5)
            h = self.addHost(f'h_{label}', ip=ip)
            self.addLink(h, sw)

        
        # External clients (to inject traffic from PCAP files)
        h_ext1 = self.addHost('ext1', ip='40.0.0.2/8')     
        h_ext2 = self.addHost('ext2', ip='120.0.0.2/8')    
        h_ext3 = self.addHost('ext3', ip='200.0.0.2/8')  
        self.addLink(h_ext1, s6)
        self.addLink(h_ext2, s6)
        self.addLink(h_ext3, s6)

        # Interconnect switches
        self.addLink(s1, s2)
        self.addLink(s1, s6)
        self.addLink(s1, s7)

        self.addLink(s2, s7)
        self.addLink(s2, s3)

        self.addLink(s3, s4)
        self.addLink(s3, s7)

        self.addLink(s4, s5)
        self.addLink(s4, s7)

        self.addLink(s5, s6)
        self.addLink(s5, s7)

        self.addLink(s6, s7)

def start():
    topo = DataControlMLTopo()
    controller = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, controller=controller, link=TCLink, autoSetMacs=True)
    net.start()
    print("DataControl-ML network started.")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    start()
