import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer

log = core.getLogger()

# =======================================================================
# MODULE 1: ACTIVE WORKER/COLLECTOR DISCOVERY (Injection)
# =======================================================================
class NodeDiscovery(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.hosts = {}
        self.fake_mac = EthAddr("00:00:00:00:11:11")
        
        # Salviamo il timer in una variabile così possiamo spegnerlo dopo!
        self.discovery_timer = Timer(10, self.inject_discovery_probes, recurring=True)
        log.info("🎯 Module 1: Node Discovery (Active Injection) initialized.")

    def inject_discovery_probes(self):
        # KILL SWITCH: Se abbiamo trovato tutti i 32 nodi, fermiamo l'iniezione
        if len(self.hosts) == 32:
            log.info("✅ Tutti i 28 Worker e i 4 Collector sono stati scoperti! Sospendo l'iniezione.")
            self.discovery_timer.cancel()
            return

        log.info("Iniezione pacchetti ARP per la scoperta dei nodi...")
        
        for connection in core.openflow.connections:
            ips_to_search = [f"10.0.0.{i}" for i in range(1, 29)] + [f"10.0.1.{i}" for i in range(1, 5)]
            
            for ip in ips_to_search:
                arp_req = arp()
                arp_req.hwsrc = self.fake_mac
                arp_req.opcode = arp.REQUEST
                arp_req.protosrc = IPAddr("10.0.0.100") 
                arp_req.protodst = IPAddr(ip)
                
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = EthAddr.BROADCAST
                ether.src = self.fake_mac
                ether.payload = arp_req
                
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                connection.send(msg)

    def _handle_PacketIn(self, event):
        eth_frame = event.parsed
        if not eth_frame.parsed: return
        
        if eth_frame.type == ethernet.ARP_TYPE and eth_frame.dst == self.fake_mac:
            arp_reply = eth_frame.payload
            
            if arp_reply.opcode == arp.REPLY:
                ip_host = str(arp_reply.protosrc)
                
                if ip_host not in self.hosts:
                    # IDENTIFICAZIONE INTELLIGENTE: Worker o Collector?
                    node_type = "WORKER" if ip_host.startswith("10.0.0.") else "COLLECTOR"
                    
                    self.hosts[ip_host] = {
                        "type": node_type,
                        "switch": event.dpid,
                        "port": event.port,
                        "mac": arp_reply.hwsrc
                    }
                    log.info(f"🔍 [DISCOVERY] Trovato {node_type} {ip_host} su Switch {dpidToStr(event.dpid)} (Porta {event.port})")

# =======================================================================
# MAIN LAUNCHER
# =======================================================================
def launch():
    core.registerNew(NodeDiscovery)
