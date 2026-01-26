import hashlib
import logging
import re
import socket
import struct
import time
from datetime import datetime
from pathlib import Path

from django.db import IntegrityError
from django.utils import timezone

from .models import Alert, LogIngestionState
from ml_features.threat_analyzer import ThreatAnalyzer


logger = logging.getLogger(__name__)

# ===== ML MODEL INITIALIZATION =====
# Lazy-load ML threat analyzer on first use
_threat_analyzer = None

def get_threat_analyzer():
    # Load threat analyzer on first call (lazy initialization)
    global _threat_analyzer
    if _threat_analyzer is None:
        try:
            _threat_analyzer = ThreatAnalyzer(models_dir='trained_models')
            logger.info("Threat analyzer initialized")
        except Exception as e:
            logger.error(f"Failed to initialize threat analyzer: {e}")
            _threat_analyzer = False  # Mark as failed
    return _threat_analyzer if _threat_analyzer is not False else None


def enrich_alert_with_ml(alert_obj):
    # Run ML analysis on alert, update fields if successful
    try:
        analyzer = get_threat_analyzer()
        if not analyzer:
            return False
        
        # Run ML prediction
        result = analyzer.analyze_alert(alert_obj)
        
        if result['error'] is not None:
            logger.warning(f"ML analysis error for alert {alert_obj.id}: {result['error']}")
            return False
        
        # Update alert with ML results
        alert_obj.ml_processed = True
        alert_obj.ml_threat_score = result['confidence']
        alert_obj.ml_classification = 'attack' if result['threat_class'] == 1 else 'benign'
        alert_obj.ml_features = result.get('features_extracted', 0)
        alert_obj.save(update_fields=['ml_processed', 'ml_threat_score', 'ml_classification', 'ml_features'])
        
        logger.debug(f"Alert {alert_obj.id} enriched: {alert_obj.ml_classification} (confidence: {alert_obj.ml_threat_score})")
        return True
    except Exception as e:
        logger.error(f"Error enriching alert {alert_obj.id} with ML: {e}")
        return False


# ===== ALERT VALIDATION FUNCTIONS =====
# Validate IP addresses, ports, and alert data before database storage

def is_valid_ipv4(ip_str):
    # Validate IPv4 format (e.g., 192.168.1.1)
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, AttributeError):
        return False


def is_valid_port(port):
    # Validate TCP/UDP port (0-65535) or None for ICMP
    if port is None:
        return True  # Ports can be None for ICMP and other protocols
    try:
        port_int = int(port)
        return 0 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def validate_alert_data(alert_dict):
    # Validate required fields, IPs, ports, threat level, and field lengths
    # Returns: (is_valid, error_msg, cleaned_data)
    errors = []
    
    # Validate required fields exist
    required_fields = ['src_ip', 'dest_ip', 'protocol', 'sid', 'message', 'threat_level', 'timestamp']
    for field in required_fields:
        if field not in alert_dict or alert_dict[field] is None:
            errors.append(f"Missing required field: {field}")
    
    if errors:
        return False, "; ".join(errors), alert_dict
    
    # Validate IP addresses
    if not is_valid_ipv4(str(alert_dict.get('src_ip', ''))):
        errors.append(f"Invalid source IP: {alert_dict.get('src_ip')}")
    
    if not is_valid_ipv4(str(alert_dict.get('dest_ip', ''))):
        errors.append(f"Invalid destination IP: {alert_dict.get('dest_ip')}")
    
    # Validate ports
    if not is_valid_port(alert_dict.get('src_port')):
        errors.append(f"Invalid source port: {alert_dict.get('src_port')}")
    
    if not is_valid_port(alert_dict.get('dest_port')):
        errors.append(f"Invalid destination port: {alert_dict.get('dest_port')}")
    
    # Validate protocol
    protocol = str(alert_dict.get('protocol', '')).strip()
    if not protocol:
        errors.append("Protocol cannot be empty")
    
    # Validate threat level
    valid_threat_levels = ['safe', 'medium', 'high']
    threat_level = str(alert_dict.get('threat_level', '')).strip().lower()
    if threat_level not in valid_threat_levels:
        errors.append(f"Invalid threat level: {alert_dict.get('threat_level')} (must be one of {valid_threat_levels})")
    
    # Validate SID
    sid = str(alert_dict.get('sid', '')).strip()
    if not sid:
        errors.append("SID cannot be empty")
    elif len(sid) > 64:
        errors.append(f"SID too long: {len(sid)} > 64 chars")
    
    # Validate message
    message = str(alert_dict.get('message', '')).strip()
    if not message:
        errors.append("Message cannot be empty")
    elif len(message) > 512:
        logger.warning(f"Message truncated from {len(message)} to 512 chars: {message[:100]}...")
        alert_dict['message'] = message[:512]
    
    # Validate classification
    classification = str(alert_dict.get('classification', '')).strip()
    if len(classification) > 255:
        logger.warning(f"Classification truncated from {len(classification)} to 255 chars")
        alert_dict['classification'] = classification[:255]
    
    if errors:
        return False, "; ".join(errors), alert_dict
    
    return True, None, alert_dict


# ===== SNORT LOG PARSING REGEX & FUNCTIONS =====
# Parse FAST format Snort logs: parse_time [sid:rev] message [classifications] [priority] {protocol} src -> dest

FAST_ALERT_PATTERN = re.compile(
    r'^(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
    r'(?P<message>.+?)\s+\[\*\*\]\s+'
    r'\[Classification:\s*(?P<classification>.*?)\]\s+'
    r'\[Priority:\s*(?P<priority>\d+)\]\s+'
    r'\{(?P<protocol>[^}]+)\}\s+'
    r'(?P<src>[^\s]+)\s+->\s+(?P<dest>[^\s]+)\s*$'
)


def parse_endpoint(endpoint):
    # Parse IP:port format, return (ip, port) or (None, None) if invalid
    if not endpoint:
        return None, None
    
    endpoint = str(endpoint).strip()
    
    if ':' not in endpoint:
        if is_valid_ipv4(endpoint):
            return endpoint, None
        return None, None
    
    ip_part, port_part = endpoint.rsplit(':', 1)
    
    if not is_valid_ipv4(ip_part):
        logger.warning(f"Invalid IP in endpoint: {ip_part}")
        return None, None
    
    if port_part.isdigit():
        port_int = int(port_part)
        if is_valid_port(port_int):
            return ip_part, port_int
        else:
            logger.warning(f"Invalid port in endpoint: {port_int}")
            return ip_part, None  # Return IP but skip invalid port
    
    return ip_part, None


# ===== PRIORITY TO THREAT LEVEL MAPPING =====
# Map Snort priority (1-3) to ThreatEye severity levels

def map_priority_to_threat_level(priority):
    # Priority 1→HIGH, 2→MEDIUM, 3→SAFE
    if priority == 1:
        return Alert.THREAT_HIGH
    if priority == 2:
        return Alert.THREAT_MEDIUM
    if priority == 3:
        return Alert.THREAT_SAFE
    return Alert.THREAT_SAFE


# ===== SNORT FAST LOG PARSING =====
# Parse individual Snort FAST format alert lines

def parse_snort_fast_line(line):
    # Parse FAST format Snort log line, validate IPs/ports/priority, return dict or None
    match = FAST_ALERT_PATTERN.match(line.strip())
    if not match:
        return None

    parts = match.groupdict()

    # Parse timestamp - need to prepend current year (Snort logs don't include year)
    timestamp_text = parts['timestamp']
    current_year = timezone.now().year
    timestamp_obj = None
    for fmt in ('%Y/%m/%d-%H:%M:%S.%f', '%Y/%m/%d-%H:%M:%S'):
        try:
            timestamp_obj = datetime.strptime(f'{current_year}/{timestamp_text}', fmt)
            break
        except ValueError:
            continue

    if timestamp_obj is None:
        logger.debug(f"Failed to parse timestamp: {timestamp_text}")
        return None

    timestamp_obj = timezone.make_aware(timestamp_obj, timezone.get_current_timezone())
    
    # Parse endpoints with validation
    src_ip, src_port = parse_endpoint(parts['src'])
    dest_ip, dest_port = parse_endpoint(parts['dest'])
    
    # Reject if critical IPs are missing/invalid
    if not src_ip or not dest_ip:
        logger.warning(f"Invalid IP addresses: src={parts['src']} -> dest={parts['dest']}")
        return None
    
    # Parse and validate priority
    try:
        priority = int(parts['priority'])
        if priority < 1 or priority > 3:
            logger.warning(f"Invalid priority {priority} (expected 1-3), defaulting to 3")
            priority = 3
    except (ValueError, TypeError):
        logger.warning(f"Failed to parse priority: {parts['priority']}")
        priority = 3
    
    # Sanitize strings and apply field length limits
    protocol = str(parts.get('protocol', 'TCP')).strip()[:20]
    sid = str(parts.get('sid', 'unknown')).strip()[:64]
    message = str(parts.get('message', 'Unknown alert')).strip()[:512]
    classification = str(parts.get('classification', '')).strip()[:255]

    return {
        'timestamp': timestamp_obj,
        'src_ip': src_ip,
        'src_port': src_port,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'protocol': protocol or 'TCP',
        'sid': sid or 'unknown',
        'message': message or 'Unknown alert',
        'classification': classification,
        'priority': priority,
        'threat_level': map_priority_to_threat_level(priority),
    }


# ===== PCAP PACKET PARSING FUNCTIONS =====
# Parse binary packet data from snort.log PCAP files

def _get_file_inode(log_file):
    # Get file inode for change detection
    stat_result = log_file.stat()
    return str(getattr(stat_result, 'st_ino', ''))


def _get_protocol_name(protocol_number):
    # Convert IP protocol number to name (6=TCP, 17=UDP, 1=ICMP)
    if protocol_number == 6:
        return 'TCP'
    if protocol_number == 17:
        return 'UDP'
    if protocol_number == 1:
        return 'ICMP'
    return f'IP-{protocol_number}'


def _parse_ipv4_packet(packet_data):
    # Extract IPv4 packet from Ethernet frame, parse IPs/ports/protocol
    # Ethernet header is 14 bytes. Parse only IPv4 frames (ethertype 0x0800).
    if len(packet_data) < 34:
        return None

    eth_type = struct.unpack('!H', packet_data[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip_start = 14
    version_ihl = packet_data[ip_start]
    version = version_ihl >> 4
    if version != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if len(packet_data) < ip_start + ihl:
        return None

    protocol_number = packet_data[ip_start + 9]
    src_ip = socket.inet_ntoa(packet_data[ip_start + 12:ip_start + 16])
    dest_ip = socket.inet_ntoa(packet_data[ip_start + 16:ip_start + 20])

    src_port = None
    dest_port = None
    transport_offset = ip_start + ihl

    if protocol_number in (6, 17) and len(packet_data) >= transport_offset + 4:
        src_port, dest_port = struct.unpack('!HH', packet_data[transport_offset:transport_offset + 4])

    return {
        'src_ip': src_ip,
        'src_port': src_port,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'protocol': _get_protocol_name(protocol_number),
    }


def _get_pcap_endian_and_data_offset(header_bytes):
    # Detect byte order from PCAP magic number
    if len(header_bytes) < 24:
        return None, None

    magic = header_bytes[:4]
    if magic == b'\xd4\xc3\xb2\xa1' or magic == b'\x4d\x3c\xb2\xa1':
        return '<', 24
    if magic == b'\xa1\xb2\xc3\xd4' or magic == b'\xa1\xb2\x3c\x4d':
        return '>', 24
    return None, None


def _parse_ipv4_packet(packet_data):
    # Ethernet header is 14 bytes. Parse only IPv4 frames (ethertype 0x0800).
    if len(packet_data) < 34:
        return None

    eth_type = struct.unpack('!H', packet_data[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip_start = 14
    version_ihl = packet_data[ip_start]
    version = version_ihl >> 4
    if version != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if len(packet_data) < ip_start + ihl:
        return None

    protocol_number = packet_data[ip_start + 9]
    src_ip = socket.inet_ntoa(packet_data[ip_start + 12:ip_start + 16])
    dest_ip = socket.inet_ntoa(packet_data[ip_start + 16:ip_start + 20])

    src_port = None
    dest_port = None
    transport_offset = ip_start + ihl

    if protocol_number in (6, 17) and len(packet_data) >= transport_offset + 4:
        src_port, dest_port = struct.unpack('!HH', packet_data[transport_offset:transport_offset + 4])

    return {
        'src_ip': src_ip,
        'src_port': src_port,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'protocol': _get_protocol_name(protocol_number),
    }


def _get_pcap_endian_and_data_offset(header_bytes):
    if len(header_bytes) < 24:
        return None, None

    magic = header_bytes[:4]
    if magic == b'\xd4\xc3\xb2\xa1' or magic == b'\x4d\x3c\xb2\xa1':
        return '<', 24
    if magic == b'\xa1\xb2\xc3\xd4' or magic == b'\xa1\xb2\x3c\x4d':
        return '>', 24
    return None, None


def ingest_snort_packet_logs(log_dir, max_packets=None):
    # Parse PCAP files, extract IPv4 packets, validate and store as alerts
    log_dir_path = Path(log_dir)
    if not log_dir_path.exists() or not log_dir_path.is_dir():
        return {'inserted': 0, 'processed_packets': 0}

    # Recursively find all packet log files (snort.log*)
    log_files = sorted(
        [p for p in log_dir_path.rglob('snort.log*') if p.is_file() and not p.name.startswith('.')],
        key=lambda p: p.name,
    )

    inserted = 0
    processed_packets = 0
    failed_packets = 0

    for log_file in log_files:
        if max_packets is not None and processed_packets >= max_packets:
            break

        try:
            file_path = str(log_file.relative_to(log_dir_path))
            inode = _get_file_inode(log_file)
            # Track ingestion state per file to resume on restart
            state, _ = LogIngestionState.objects.get_or_create(file_path=file_path)

            # File was rotated/replaced - reset offset and inode
            if state.inode != inode:
                state.inode = inode
                state.offset = 0

            with log_file.open('rb') as handle:
                global_header = handle.read(24)
                endian, data_offset = _get_pcap_endian_and_data_offset(global_header)
                if endian is None:
                    continue

                file_size = log_file.stat().st_size
                if state.offset == 0:
                    state.offset = data_offset
                if state.offset < data_offset or state.offset > file_size:
                    state.offset = data_offset

                handle.seek(state.offset)

                while True:
                    if max_packets is not None and processed_packets >= max_packets:
                        break

                    packet_header = handle.read(16)
                    if len(packet_header) < 16:
                        break

                    try:
                        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(f'{endian}IIII', packet_header)
                    except struct.error:
                        break

                    packet_data = handle.read(incl_len)
                    if len(packet_data) < incl_len:
                        break

                    processed_packets += 1
                    parsed_packet = _parse_ipv4_packet(packet_data)
                    if not parsed_packet:
                        continue

                    timestamp = timezone.make_aware(
                        datetime.fromtimestamp(ts_sec + (ts_usec / 1_000_000.0)),
                        timezone.get_current_timezone(),
                    )

                    # Build alert dict from parsed packet data
                    packet_alert = {
                        'timestamp': timestamp,
                        'src_ip': parsed_packet['src_ip'],
                        'src_port': parsed_packet['src_port'],
                        'dest_ip': parsed_packet['dest_ip'],
                        'dest_port': parsed_packet['dest_port'],
                        'protocol': parsed_packet['protocol'],
                        'sid': 'packet_capture',
                        'message': 'Real-time packet captured from snort.log',
                        'classification': 'Packet Log',
                        'priority': 3,
                        'threat_level': Alert.THREAT_SAFE,
                    }
                    
                    # Validate packet alert data before storing
                    is_valid, error_msg, cleaned_packet = validate_alert_data(packet_alert)
                    if not is_valid:
                        failed_packets += 1
                        logger.warning(f'Invalid packet data: {error_msg}')
                        continue

                    hash_source = f"{file_path}:{ts_sec}:{ts_usec}:{parsed_packet['src_ip']}:{parsed_packet['dest_ip']}:{incl_len}"
                    event_hash = hashlib.sha256(hash_source.encode('utf-8')).hexdigest()

                    try:
                        alert = Alert.objects.create(
                            **cleaned_packet,
                            raw_line=f"pcap:{file_path}:{ts_sec}.{ts_usec}:{parsed_packet['src_ip']}->{parsed_packet['dest_ip']}",
                            event_hash=event_hash,
                        )
                        inserted += 1
                        # Enrich alert with ML analysis
                        enrich_alert_with_ml(alert)
                    except IntegrityError:
                        continue
                    except Exception:
                        failed_packets += 1
                        logger.exception('Failed to store parsed packet from %s', file_path)
                        continue

                state.offset = handle.tell()

            state.save(update_fields=['inode', 'offset', 'updated_at'])
        except Exception:
            logger.exception('Error while ingesting packet log file %s', log_file)
            continue

    return {
        'inserted': inserted,
        'processed_packets': processed_packets,
        'failed_packets': failed_packets,
    }


def ingest_snort_logs(log_dir, max_lines=None):
    # Parse FAST format alert logs, validate, deduplicate via event_hash, store alerts
    log_dir_path = Path(log_dir)
    if not log_dir_path.exists() or not log_dir_path.is_dir():
        logger.warning(f'Log directory does not exist: {log_dir}')
        return {'inserted': 0, 'processed_lines': 0, 'failed_lines': 0}

    # Find all alert log files (filename contains "alert")
    log_files = sorted(
        [p for p in log_dir_path.rglob('*alert*') if p.is_file() and p.suffix != '.gz' and not p.name.startswith('.')],
        key=lambda p: p.name,
    )
    
    logger.debug(f'Found {len(log_files)} alert files in {log_dir}')

    inserted = 0
    processed_lines = 0
    failed_lines = 0

    for log_file in log_files:
        if max_lines is not None and processed_lines >= max_lines:
            break

        try:
            file_path = str(log_file.relative_to(log_dir_path))
            inode = _get_file_inode(log_file)
            # Track ingestion state per file to resume on restart
            state, _ = LogIngestionState.objects.get_or_create(file_path=file_path)

            # File was rotated/replaced - reset offset and inode
            if state.inode != inode:
                state.inode = inode
                state.offset = 0

            file_size = log_file.stat().st_size
            if state.offset > file_size:
                state.offset = 0

            with log_file.open('r', encoding='utf-8', errors='ignore') as handle:
                handle.seek(state.offset)
                while True:
                    if max_lines is not None and processed_lines >= max_lines:
                        break

                    line_start = handle.tell()
                    line = handle.readline()
                    if not line:
                        break

                    processed_lines += 1
                    # Parse FAST format line
                    parsed = parse_snort_fast_line(line)
                    if not parsed:
                        continue

                    # Validate parsed fields
                    is_valid, error_msg, cleaned_data = validate_alert_data(parsed)
                    if not is_valid:
                        failed_lines += 1
                        logger.warning(f'Invalid alert data from {file_path}: {error_msg}')
                        continue

                    # Create unique hash for deduplication (same line = same event)
                    hash_source = f'{file_path}:{line_start}:{line.strip()}'
                    event_hash = hashlib.sha256(hash_source.encode('utf-8')).hexdigest()

                    try:
                        alert = Alert.objects.create(
                            **cleaned_data,
                            raw_line=line.strip(),
                            event_hash=event_hash,
                        )
                        inserted += 1
                        # Enrich alert with ML analysis
                        enrich_alert_with_ml(alert)
                    except IntegrityError:
                        # Duplicate alert (same event_hash) - skip
                        continue
                    except Exception:
                        failed_lines += 1
                        logger.exception(f'Failed to store validated alert from {file_path}')
                        continue

                state.offset = handle.tell()

            # Save progress (file offset + inode) for resume on restart
            state.save(update_fields=['inode', 'offset', 'updated_at'])
        except Exception:
            logger.exception('Error while ingesting alert log file %s', log_file)
            continue

    logger.info(f'Snort logs ingestion complete: inserted={inserted}, processed_lines={processed_lines}, failed={failed_lines}')
    return {
        'inserted': inserted,
        'processed_lines': processed_lines,
        'failed_lines': failed_lines,
    }


# ===== CONTINUOUS LOG INGESTION POLLING =====
# Continuously monitor and ingest Snort logs

def run_polling_loop(log_dir, interval_seconds=3):
    """
    Continuously monitor Snort log directory and ingest new alerts.
    
    Polling cycle:
    1. Call ingest_snort_logs() - parse text-based FAST format alerts
    2. Call ingest_snort_packet_logs() - parse binary PCAP packets
    3. Sleep for interval_seconds
    4. Repeat forever
    
    Designed to run as background process or management command.
    Logs results of each ingestion cycle.
    
    Args:
        log_dir: Path to Snort log directory
        interval_seconds: Delay between polling cycles (default 3 seconds)
    """
    while True:
        try:
            # Ingest text-based FAST format logs
            text_result = ingest_snort_logs(log_dir)
            # Ingest binary PCAP packet logs
            packet_result = ingest_snort_packet_logs(log_dir)

            logger.info(
                'Snort ingest cycle complete: text=%s packet=%s',
                text_result,
                packet_result,
            )
        except Exception:
            logger.exception('Unhandled error in snort polling loop')

        time.sleep(max(1, interval_seconds))
