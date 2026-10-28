import time
import math
import threading
from collections import defaultdict
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)

# Safely import Scapy to prevent crashes if it or npcap/libpcap is missing
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    logger.warning(f"Scapy import failed: {e}. Network monitoring will be disabled.")
    class IP: pass
    class TCP: pass
    class UDP: pass
    class ICMP: pass
    class ARP: pass
    class DNS: pass
    class DNSQR: pass

class NetworkCollector(threading.Thread):
    def __init__(self, event_bus: EventBus, interface: str = None, enabled: bool = True):
        super().__init__(daemon=True)
        self.event_bus = event_bus
        self.interface = interface if interface else None
        self.enabled = enabled
        self.running = True
        
        # Stateful tables for anomaly detection
        self.port_scan_state = defaultdict(list)    # ip: [(port, timestamp)]
        self.arp_table = {}                         # ip: mac
        self.beacon_state = defaultdict(list)       # (src, dst): [timestamps]
        self.alerted_ips = defaultdict(float)       # alert_key: last_alert_time (rate limiting)

    def run(self):
        if not self.enabled:
            logger.info("NetworkCollector is disabled in config.")
            return
            
        if not SCAPY_AVAILABLE:
            logger.error("NetworkCollector cannot start because Scapy or required drivers (Npcap/libpcap) are missing.")
            return

        logger.info(f"Starting Scapy network sniffer on interface: {self.interface or 'default'}")
        try:
            # Sniff packet loop (store=0 ensures memory doesn't leak)
            sniff(
                iface=self.interface, 
                prn=self.packet_callback, 
                store=0, 
                stop_filter=self.stop_filter
            )
        except (PermissionError, OSError) as e:
            logger.warning(
                f"[WARNING] Network packet capture requires elevated privileges (sudo/root): {e}. "
                "Network sniffing disabled. Non-privileged features (Dashboard, Log Monitoring, Rule Engine) continue running normally."
            )
        except Exception as e:
            logger.warning(f"Network sniffer encountered an error: {e}. Sniffing disabled.")

    def stop(self):
        self.running = False

    def stop_filter(self, packet):
        return not self.running

    def packet_callback(self, packet):
        try:
            # Process ARP Traffic
            if packet.haslayer(ARP):
                self._process_arp(packet)
            
            # Process IP Traffic (TCP / UDP / ICMP)
            elif packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # 1. TCP Processing
                if packet.haslayer(TCP):
                    self._process_tcp(packet, src_ip, dst_ip)
                
                # 2. UDP Processing
                elif packet.haslayer(UDP):
                    self._process_udp(packet, src_ip, dst_ip)
                
                # 3. ICMP Processing
                elif packet.haslayer(ICMP):
                    self._process_icmp(packet, src_ip, dst_ip)

        except Exception as e:
            # Ensure packet parsing errors never crash the packet capture thread
            pass

    def _process_arp(self, packet):
        arp_layer = packet[ARP]
        op = arp_layer.op # 1 for request, 2 for reply
        psrc = arp_layer.psrc
        hwsrc = arp_layer.hwsrc
        pdst = arp_layer.pdst
        hwdst = arp_layer.hwdst

        # Emit raw ARP packet event to rules engine
        event = {
            "logsource": "network",
            "event_type": "arp_packet",
            "ip": psrc,
            "src_mac": hwsrc,
            "dst_ip": pdst,
            "dst_mac": hwdst,
            "op": op
        }
        self.event_bus.publish("normalized_event", event)

        # Detect ARP Spoofing
        if op == 2: # Reply
            if psrc in self.arp_table:
                old_mac = self.arp_table[psrc]
                if old_mac.lower() != hwsrc.lower():
                    alert_key = f"arp_spoof_{psrc}"
                    if time.time() - self.alerted_ips[alert_key] > 10:
                        self.alerted_ips[alert_key] = time.time()
                        logger.warning(f"ARP SPOOFING DETECTED: IP {psrc} was {old_mac}, now associated with {hwsrc}!")
                        
                        # Publish anomaly
                        anomaly = {
                            "logsource": "network",
                            "event_type": "arp_spoofing",
                            "ip": psrc,
                            "old_mac": old_mac,
                            "new_mac": hwsrc,
                            "raw_log": f"ARP Poisoning detected: IP {psrc} mapping modified from {old_mac} to {hwsrc}"
                        }
                        self.event_bus.publish("normalized_event", anomaly)
            self.arp_table[psrc] = hwsrc

    def _process_tcp(self, packet, src_ip, dst_ip):
        tcp_layer = packet[TCP]
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = tcp_layer.flags

        # Emit raw TCP packet event to rules engine (e.g. for Flood counts)
        event = {
            "logsource": "network",
            "event_type": "tcp_packet",
            "ip": src_ip,
            "dst_ip": dst_ip,
            "sport": sport,
            "dport": dport,
            "flags": str(flags)
        }
        self.event_bus.publish("normalized_event", event)

        # Process Connection attempts (SYN set, ACK not set)
        is_syn = (flags & 0x02) and not (flags & 0x10)
        if is_syn:
            syn_event = {
                "logsource": "network",
                "event_type": "tcp_syn",
                "ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dport
            }
            self.event_bus.publish("normalized_event", syn_event)

            # Port Scan Stateful Tracker
            now = time.time()
            self.port_scan_state[src_ip].append((dport, now))
            # Sliding window of 10 seconds
            self.port_scan_state[src_ip] = [x for x in self.port_scan_state[src_ip] if now - x[1] <= 10]
            
            # Check unique port threshold
            unique_ports = set(x[0] for x in self.port_scan_state[src_ip])
            if len(unique_ports) > 15:
                alert_key = f"port_scan_{src_ip}"
                if now - self.alerted_ips[alert_key] > 10:
                    self.alerted_ips[alert_key] = now
                    logger.warning(f"PORT SCAN DETECTED: IP {src_ip} scanned {len(unique_ports)} ports in 10s.")
                    
                    anomaly = {
                        "logsource": "network",
                        "event_type": "port_scan",
                        "ip": src_ip,
                        "ports_scanned": list(unique_ports),
                        "raw_log": f"Port scan detected: {src_ip} queried {len(unique_ports)} unique ports in 10s."
                    }
                    self.event_bus.publish("normalized_event", anomaly)

        # Detect Suspicious TCP Flag Combinations
        is_suspicious = False
        pattern_desc = ""
        if flags == 0:
            is_suspicious = True
            pattern_desc = "TCP Null Scan (no flags set)"
        elif flags == 0x29: # FIN (1) + PSH (8) + URG (32)
            is_suspicious = True
            pattern_desc = "TCP Xmas Scan (FIN, PSH, URG flags set)"
        elif (flags & 0x03) == 0x03: # SYN (2) + FIN (1)
            is_suspicious = True
            pattern_desc = "Invalid flags Combination (SYN + FIN)"

        if is_suspicious:
            alert_key = f"susp_packet_{src_ip}_{flags}"
            if time.time() - self.alerted_ips[alert_key] > 10:
                self.alerted_ips[alert_key] = time.time()
                logger.warning(f"SUSPICIOUS PACKET: {pattern_desc} from {src_ip}")
                
                anomaly = {
                    "logsource": "network",
                    "event_type": "suspicious_packet",
                    "ip": src_ip,
                    "dst_ip": dst_ip,
                    "flags": str(flags),
                    "raw_log": f"Suspicious packet patterns: {src_ip} -> {dst_ip} matched {pattern_desc}"
                }
                self.event_bus.publish("normalized_event", anomaly)

        # Trace Network Beaconing Patterns
        self._check_beaconing(src_ip, dst_ip)

    def _process_udp(self, packet, src_ip, dst_ip):
        udp_layer = packet[UDP]
        sport = udp_layer.sport
        dport = udp_layer.dport

        # Emit raw UDP event
        event = {
            "logsource": "network",
            "event_type": "udp_packet",
            "ip": src_ip,
            "dst_ip": dst_ip,
            "sport": sport,
            "dport": dport
        }
        self.event_bus.publish("normalized_event", event)

        # Analyze DNS queries
        if dport == 53 and packet.haslayer(DNS):
            dns_layer = packet[DNS]
            # qr == 0 means Query
            if dns_layer.qr == 0 and packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname
                if qname:
                    qname_str = qname.decode('utf-8', errors='ignore').strip('.')
                    
                    # Emit raw DNS query event (for DNS Flooding rules)
                    dns_event = {
                        "logsource": "network",
                        "event_type": "dns_query",
                        "ip": src_ip,
                        "dst_ip": dst_ip,
                        "query": qname_str
                    }
                    self.event_bus.publish("normalized_event", dns_event)

                    # Detect DNS Tunneling
                    if len(qname_str) > 60:
                        # Calculate Shannon Entropy of the domain label to check for encoding
                        prob = [float(qname_str.count(c)) / len(qname_str) for c in dict.fromkeys(qname_str)]
                        entropy = -sum(p * math.log(p, 2) for p in prob)
                        
                        if entropy > 4.2:
                            alert_key = f"dns_tunnel_{src_ip}"
                            if time.time() - self.alerted_ips[alert_key] > 10:
                                self.alerted_ips[alert_key] = time.time()
                                logger.warning(f"DNS TUNNELING DETECTED: IP {src_ip} query: {qname_str} (Entropy: {round(entropy, 2)})")
                                
                                anomaly = {
                                    "logsource": "network",
                                    "event_type": "dns_tunneling",
                                    "ip": src_ip,
                                    "query": qname_str,
                                    "entropy": round(entropy, 2),
                                    "raw_log": f"Suspected DNS Tunnel: {src_ip} made query with high entropy ({round(entropy, 2)}): {qname_str}"
                                }
                                self.event_bus.publish("normalized_event", anomaly)

    def _process_icmp(self, packet, src_ip, dst_ip):
        icmp_layer = packet[ICMP]
        # Type 8 = Echo request (ping)
        if icmp_layer.type == 8:
            event = {
                "logsource": "network",
                "event_type": "icmp_ping",
                "ip": src_ip,
                "dst_ip": dst_ip
            }
            self.event_bus.publish("normalized_event", event)

    def _check_beaconing(self, src_ip, dst_ip):
        now = time.time()
        key = (src_ip, dst_ip)
        self.beacon_state[key].append(now)
        # Store only the last 6 communication times
        self.beacon_state[key] = self.beacon_state[key][-6:]

        if len(self.beacon_state[key]) >= 5:
            timestamps = self.beacon_state[key]
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_interval = sum(intervals) / len(intervals)
            
            # Calculate variance of intervals
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # If the intervals are highly regular (variance < 0.25)
            # and it is within an active beacon window (1.0 to 60.0 seconds)
            if variance < 0.25 and 1.0 <= avg_interval <= 60.0:
                alert_key = f"beaconing_{src_ip}_{dst_ip}"
                if now - self.alerted_ips[alert_key] > 30: # 30s rate-limit
                    self.alerted_ips[alert_key] = now
                    logger.warning(f"BEACONING DETECTED: IP {src_ip} contacting {dst_ip} every {round(avg_interval, 2)}s.")
                    
                    anomaly = {
                        "logsource": "network",
                        "event_type": "beaconing",
                        "ip": src_ip,
                        "dst_ip": dst_ip,
                        "interval": round(avg_interval, 2),
                        "raw_log": f"Periodic network beaconing: {src_ip} calling out to {dst_ip} every {round(avg_interval, 2)} seconds."
                    }
                    self.event_bus.publish("normalized_event", anomaly)
