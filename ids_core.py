#!/usr/bin/env python3
"""
Core IDS functionality for packet capture, analysis, and detection.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
import json
import re
from datetime import datetime, timedelta
from typing import Optional

try:
    from notifier import Notifier
except Exception:
    Notifier = None


class IDSCore:
    """Core IDS engine for packet analysis and threat detection."""
    
    def __init__(self, config_file="ids_config.json"):
        self.config = self.load_config(config_file)
        self.running = False
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = None
        
        # Statistics tracking
        self.stats = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'attacks_detected': defaultdict(int),
            'top_sources': defaultdict(int),
            'top_destinations': defaultdict(int),
            'protocols': defaultdict(int)
        }
        
        # Anomaly detection
        self.connection_rates = defaultdict(lambda: deque(maxlen=100))
        self.packet_sizes = deque(maxlen=1000)
        self.port_scan_attempts = defaultdict(int)
        
        # Setup logging
        self.setup_logging()
        
        # Setup notifier
        self.notifier: Optional[object] = None
        try:
            if Notifier is not None:
                self.notifier = Notifier(self.config, logger_name=__name__)
        except Exception:
            # Do not break if notifier fails to init
            self.notifier = None
        
    def load_config(self, config_file):
        """Load IDS configuration from JSON file."""
        default_config = {
            "interface": "any",
            "signature_rules": {
                "port_scan_threshold": 10,
                "syn_flood_threshold": 50,
                "large_packet_threshold": 1500,
                "suspicious_ports": [23, 135, 139, 445, 1433, 3389],
                "blocked_ips": [],
                "allowed_ips": []
            },
            "web_signatures": {
                "enabled": True,
                "inspect_ports": [80, 8080, 8000, 443],
                "max_payload_len": 4096
            },
            "anomaly_detection": {
                "enabled": True,
                "connection_rate_threshold": 20,
                "packet_size_deviation": 2.0
            },
            "logging": {
                "level": "INFO",
                "file": "ids.log",
                "max_size": "10MB"
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            # Create default config file
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config
    
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config['logging']['level'].upper())
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['logging']['file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def packet_callback(self, packet):
        """Main packet processing callback."""
        if not self.running:
            return
            
        self.packet_count += 1
        self.stats['packets_analyzed'] += 1
        
        try:
            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            if not packet_info:
                return
                
            # Update statistics
            self.update_statistics(packet_info)
            
            # Run detection algorithms
            alerts = self.detect_threats(packet_info)
            
            # Process alerts
            for alert in alerts:
                self.handle_alert(alert, packet_info)
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def extract_packet_info(self, packet):
        """Extract relevant information from packet."""
        packet_info = {
            'timestamp': datetime.now(),
            'size': len(packet),
            'protocol': 'unknown'
        }
        
        # IP layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info.update({
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'ttl': ip_layer.ttl
            })
            
            # TCP layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': tcp_layer.flags,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack
                })

                # Try to extract HTTP metadata and payload for web attack detection
                try:
                    if packet.haslayer(HTTPRequest):
                        http = packet[HTTPRequest]
                        packet_info.update({
                            'http_method': bytes(http.Method or b'').decode(errors='ignore'),
                            'http_host': bytes(http.Host or b'').decode(errors='ignore'),
                            'http_path': bytes(http.Path or b'').decode(errors='ignore')
                        })
                    elif packet.haslayer(HTTPResponse):
                        # We generally analyze requests for signatures; response kept minimal
                        packet_info.setdefault('http_response', True)

                    # Fallback to Raw payload decode (bounded)
                    if packet.haslayer(Raw):
                        raw_bytes = bytes(packet[Raw].load or b'')
                        if raw_bytes:
                            # Limit payload to avoid excessive memory/cost
                            max_len = self.config.get('web_signatures', {}).get('max_payload_len', 4096)
                            snippet = raw_bytes[:max_len]
                            try:
                                http_payload = snippet.decode('utf-8', errors='ignore')
                            except Exception:
                                http_payload = ''
                            if http_payload:
                                packet_info['http_payload'] = http_payload
                except Exception:
                    # Never let parsing errors break capture loop
                    pass
                
            # UDP layer
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport
                })
                
            # ICMP layer
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code
                })
        
        return packet_info
    
    def update_statistics(self, packet_info):
        """Update IDS statistics."""
        if 'src_ip' in packet_info:
            self.stats['top_sources'][packet_info['src_ip']] += 1
        if 'dst_ip' in packet_info:
            self.stats['top_destinations'][packet_info['dst_ip']] += 1
        if 'protocol' in packet_info:
            self.stats['protocols'][packet_info['protocol']] += 1
            
        # Track packet sizes for anomaly detection
        self.packet_sizes.append(packet_info['size'])
    
    def detect_threats(self, packet_info):
        """Run all detection algorithms on packet."""
        alerts = []
        
        # Signature-based detection
        alerts.extend(self.signature_detection(packet_info))
        
        # Anomaly detection
        if self.config['anomaly_detection']['enabled']:
            alerts.extend(self.anomaly_detection(packet_info))
        
        return alerts
    
    def signature_detection(self, packet_info):
        """Signature-based threat detection."""
        alerts = []
        rules = self.config['signature_rules']
        
        # Port scan detection
        if self.detect_port_scan(packet_info, rules):
            alerts.append({
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'description': f'Port scan detected from {packet_info["src_ip"]}',
                'source': packet_info['src_ip'],
                'details': packet_info
            })
        
        # SYN flood detection
        if self.detect_syn_flood(packet_info, rules):
            alerts.append({
                'type': 'SYN_FLOOD',
                'severity': 'HIGH',
                'description': f'SYN flood detected from {packet_info["src_ip"]}',
                'source': packet_info['src_ip'],
                'details': packet_info
            })
        
        # Suspicious port access
        if self.detect_suspicious_port(packet_info, rules):
            alerts.append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM',
                'description': f'Access to suspicious port {packet_info["dst_port"]} from {packet_info["src_ip"]}',
                'source': packet_info['src_ip'],
                'details': packet_info
            })
        
        # Large packet detection
        if packet_info['size'] > rules['large_packet_threshold']:
            alerts.append({
                'type': 'LARGE_PACKET',
                'severity': 'LOW',
                'description': f'Large packet detected: {packet_info["size"]} bytes',
                'source': packet_info.get('src_ip', 'unknown'),
                'details': packet_info
            })
        
        # Web attack signatures
        alerts.extend(self.detect_web_attacks(packet_info))

        return alerts
    
    def detect_port_scan(self, packet_info, rules):
        """Detect port scanning attempts."""
        if 'src_ip' in packet_info and 'dst_port' in packet_info:
            key = packet_info['src_ip']
            self.port_scan_attempts[key] += 1
            
            # Check if threshold exceeded
            if self.port_scan_attempts[key] > rules['port_scan_threshold']:
                return True
        return False
    
    def detect_syn_flood(self, packet_info, rules):
        """Detect SYN flood attacks."""
        if (packet_info.get('flags') == 2 and  # SYN flag
            'src_ip' in packet_info):
            key = packet_info['src_ip']
            self.connection_rates[key].append(time.time())
            
            # Check recent connection rate
            now = time.time()
            recent_connections = [t for t in self.connection_rates[key] if now - t < 60]
            
            if len(recent_connections) > rules['syn_flood_threshold']:
                return True
        return False
    
    def detect_suspicious_port(self, packet_info, rules):
        """Detect access to suspicious ports."""
        if 'dst_port' in packet_info:
            return packet_info['dst_port'] in rules['suspicious_ports']
        return False
    
    def anomaly_detection(self, packet_info):
        """Basic anomaly detection based on statistical analysis."""
        alerts = []
        
        # Packet size anomaly
        if len(self.packet_sizes) > 100:
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
            std_dev = (sum((x - avg_size) ** 2 for x in self.packet_sizes) / len(self.packet_sizes)) ** 0.5
            
            if abs(packet_info['size'] - avg_size) > self.config['anomaly_detection']['packet_size_deviation'] * std_dev:
                alerts.append({
                    'type': 'SIZE_ANOMALY',
                    'severity': 'MEDIUM',
                    'description': f'Unusual packet size: {packet_info["size"]} bytes',
                    'source': packet_info.get('src_ip', 'unknown'),
                    'details': packet_info
                })
        
        return alerts

    def detect_web_attacks(self, packet_info):
        """Detect common web attack patterns in HTTP traffic (best-effort)."""
        alerts = []
        web_cfg = self.config.get('web_signatures', {"enabled": False})
        if not web_cfg.get('enabled', False):
            return alerts

        dst_port = packet_info.get('dst_port')
        http_payload = packet_info.get('http_payload', '')
        http_path = packet_info.get('http_path', '')
        http_method = packet_info.get('http_method', '')

        # Only inspect common web ports if known
        if dst_port is not None and dst_port not in web_cfg.get('inspect_ports', [80, 8080, 8000, 443]):
            return alerts

        haystack = (http_method + ' ' + http_path + '\n' + http_payload).lower()
        if not haystack.strip():
            return alerts

        # Regex patterns (lightweight, case-insensitive by lowercasing)
        patterns = [
            ('SQLI', r"('|%27|\bunion\b|\bor\b\s+\d=\d|\bselect\b|--|/\*|\bupdate\b|\binsert\b|\bdrop\b)"),
            ('XSS', r"(<script|%3cscript|onerror=|onload=|alert\(|javascript:|document\.cookie)"),
            ('PATH_TRAVERSAL', r"(\.\./|%2e%2e%2f|\.\.\\)"),
            ('LFI', r"(etc/passwd|\bproc/self/|\bwindows\\system32|\bboot\.ini)"),
            ('RFI', r"(http://|https://).*(\?.*=http|\?.*=https)"),
            ('CMD_INJECTION', r"(;|&&|\|\|)\s*(cat|ls|whoami|id|nc|bash|sh|powershell)\b")
        ]

        matched_types = []
        for attack_type, regex in patterns:
            try:
                if re.search(regex, haystack):
                    matched_types.append(attack_type)
            except re.error:
                continue

        for attack_type in matched_types:
            severity = 'HIGH' if attack_type in ('SQLI', 'CMD_INJECTION', 'RFI') else 'MEDIUM'
            desc = f"Possible {attack_type.replace('_', ' ')} in HTTP request"
            alerts.append({
                'type': attack_type,
                'severity': severity,
                'description': desc,
                'source': packet_info.get('src_ip', 'unknown'),
                'details': {
                    'method': http_method,
                    'path': http_path[:256],
                    'snippet': http_payload[:256] if http_payload else ''
                }
            })

        return alerts
    
    def handle_alert(self, alert, packet_info):
        """Handle generated alerts."""
        self.alert_count += 1
        self.stats['alerts_generated'] += 1
        self.stats['attacks_detected'][alert['type']] += 1
        
        # Log alert
        self.logger.warning(f"ALERT: {alert['type']} - {alert['description']}")
        
        # Store alert for GUI display
        alert['timestamp'] = datetime.now()
        alert['id'] = self.alert_count
        
        # Emit alert signal for GUI (will be connected by GUI)
        if hasattr(self, 'alert_callback'):
            self.alert_callback(alert)
        
        # Send notifications if configured
        try:
            if self.notifier is not None:
                self.notifier.maybe_notify(alert)
        except Exception:
            # Never let notification failures impact core processing
            pass
    
    def start_monitoring(self, interface=None):
        """Start packet monitoring."""
        if self.running:
            return False
            
        self.running = True
        self.start_time = datetime.now()
        interface = interface or self.config['interface']
        
        self.logger.info(f"Starting IDS monitoring on interface: {interface}")
        
        # Start packet capture in separate thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface,),
            daemon=True
        )
        self.capture_thread.start()
        
        return True
    
    def _capture_packets(self, interface):
        """Internal packet capture method."""
        try:
            sniff(
                iface=interface,
                prn=self.packet_callback,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
    
    def stop_monitoring(self):
        """Stop packet monitoring."""
        self.running = False
        self.logger.info("IDS monitoring stopped")
    
    def get_statistics(self):
        """Get current IDS statistics."""
        uptime = datetime.now() - self.start_time if self.start_time else timedelta(0)
        
        return {
            'uptime': str(uptime),
            'packets_analyzed': self.stats['packets_analyzed'],
            'alerts_generated': self.stats['alerts_generated'],
            'attacks_detected': dict(self.stats['attacks_detected']),
            'top_sources': dict(sorted(self.stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_destinations': dict(sorted(self.stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'protocols': dict(self.stats['protocols']),
            'running': self.running
        }
    
    def set_alert_callback(self, callback):
        """Set callback function for alerts (used by GUI)."""
        self.alert_callback = callback


if __name__ == "__main__":
    # Test the IDS core
    ids = IDSCore()
    
    def test_alert_callback(alert):
        print(f"Test Alert: {alert}")
    
    ids.set_alert_callback(test_alert_callback)
    
    try:
        print("Starting IDS test...")
        ids.start_monitoring()
        
        # Run for 30 seconds
        time.sleep(30)
        
    except KeyboardInterrupt:
        print("Stopping IDS...")
    finally:
        ids.stop_monitoring()
        print("IDS stopped.")
        print("Statistics:", ids.get_statistics())
