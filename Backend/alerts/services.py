import hashlib
import logging
import os
import re
import socket
import struct
import threading
import time
from datetime import datetime
from pathlib import Path

from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.db import IntegrityError
from django.utils import timezone

from .models import Alert, LogIngestionState
from ml_features.threat_analyzer import ThreatAnalyzer
from authentication.models import Organization, User
from subscription.models import SubscriptionPlan


logger = logging.getLogger(__name__)

# ===== EMAIL NOTIFICATION FOR ALERTS =====
# Send email notifications for MEDIUM and HIGH severity alerts
# Rate limited: only send 1 email per severity level per 10 seconds to avoid spam

_last_email_time_high = {}  # org_id -> timestamp
_last_email_time_medium = {}  # org_id -> timestamp
EMAIL_RATE_LIMIT_SECONDS = 10  # Wait at least 10 seconds between emails per severity

def send_alert_notification(alert):
    """
    Send email notification for MEDIUM and HIGH severity alerts.
    Rate limited to avoid spam: max 1 email per severity per 10 seconds per org.
    
    Args:
        alert: Alert object to send notification for
    """
    # Only send for MEDIUM and HIGH severity alerts
    if alert.threat_level not in [Alert.THREAT_MEDIUM, Alert.THREAT_HIGH]:
        return
    
    try:
        # Get all organizations with email alerts enabled
        organizations = Organization.objects.filter(is_active=True)
        
        for org in organizations:
            # Get subscription plan for this organization tier
            if org.subscription_tier == Organization.TIER_NOT_SUBSCRIBED:
                continue
            
            # Check if any plan allows email alerts
            plans_with_email = SubscriptionPlan.objects.filter(email_alerts_enabled=True)
            if not plans_with_email.exists():
                continue
            
            # Get all active users from this organization
            all_org_users = User.objects.filter(
                organization=org,
                is_active=True,
                is_verified=True
            )
            recipient_emails = [user.email for user in all_org_users if user.email]
            
            if not recipient_emails:
                logger.debug(f"No recipients found for alert {alert.id}")
                continue
            
            # Check rate limit - only send 1 email per severity type per org every N seconds
            now = timezone.now().timestamp()
            if alert.threat_level == Alert.THREAT_HIGH:
                last_time = _last_email_time_high.get(org.id, 0)
                if now - last_time < EMAIL_RATE_LIMIT_SECONDS:
                    continue  # Skip this email - rate limited
                _last_email_time_high[org.id] = now
            else:
                last_time = _last_email_time_medium.get(org.id, 0)
                if now - last_time < EMAIL_RATE_LIMIT_SECONDS:
                    continue  # Skip this email - rate limited
                _last_email_time_medium[org.id] = now
            
            # Prepare email content - simple and focused
            subject = f'🛡 ThreatEye Alert: {alert.threat_level.upper()} - {alert.message[:50]}'
            
            text_content = f"""THREATEYE SECURITY ALERT

Timestamp: {alert.timestamp.isoformat()}

Message:
{alert.message}

Classification:
{alert.classification or 'N/A'}

Signature ID:
{alert.sid}

Source IP: {alert.src_ip}
Destination IP: {alert.dest_ip}
"""
            
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #5b4fd1 0%, #7c3aed 100%); color: #ffffff; padding: 30px; text-align: center; }}
        .header-title {{ font-size: 24px; font-weight: bold; margin: 0; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 25px; }}
        .section-title {{ font-size: 13px; letter-spacing: 2px; color: #6b7280; text-transform: uppercase; font-weight: 600; margin-bottom: 12px; }}
        .section-content {{ background-color: #f9fafb; border-left: 4px solid #7c3aed; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 14px; color: #1f2937; line-height: 1.6; }}
        .message-box {{ background-color: #fef2f2; border-left: 4px solid #dc2626; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
        .message-label {{ font-weight: 600; color: #991b1b; font-size: 13px; margin-bottom: 8px; }}
        .message-text {{ color: #7f1d1d; font-size: 16px; }}
        .detail-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e5e7eb; }}
        .detail-row:last-child {{ border-bottom: none; }}
        .detail-label {{ font-weight: 600; color: #6b7280; font-size: 13px; }}
        .detail-value {{ color: #1f2937; }}
        .footer {{ background-color: #f3f4f6; color: #6b7280; padding: 20px; text-align: center; font-size: 12px; border-top: 1px solid #e5e7eb; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">🛡 ThreatEye Security Alert</div>
        </div>
        
        <div class="content">
            <div class="message-box">
                <div class="message-label">⚠ {alert.threat_level.upper()} SEVERITY</div>
                <div class="message-text">{alert.message}</div>
            </div>
            
            <div class="section">
                <div class="section-title">Classification</div>
                <div class="section-content">
                    {alert.classification or 'N/A'}
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Signature ID</div>
                <div class="section-content">
                    {alert.sid}
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Network Details</div>
                <div class="section-content">
                    <div class="detail-row">
                        <span class="detail-label">Source IP:</span>
                        <span class="detail-value">{alert.src_ip}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Destination IP:</span>
                        <span class="detail-value">{alert.dest_ip}</span>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Timestamp</div>
                <div class="section-content">
                    {alert.timestamp.isoformat()}
                </div>
            </div>
        </div>
        
        <div class="footer">
            ThreatEye Intrusion Detection System
        </div>
    </div>
</body>
</html>"""
            
            # Send email synchronously with proper error handling
            for recipient_email in recipient_emails:
                try:
                    msg = EmailMultiAlternatives(
                        subject=subject,
                        body=text_content,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[recipient_email]
                    )
                    msg.attach_alternative(html_content, "text/html")
                    result = msg.send()
                    if result:
                        logger.info(f"[Alert Email] Sent to {recipient_email} for alert {alert.id} ({alert.threat_level})")
                    else:
                        logger.warning(f"[Alert Email] Failed to send to {recipient_email}")
                except Exception as e:
                    logger.error(f"[Alert Email] Error sending to {recipient_email}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error in send_alert_notification for alert {alert.id}: {str(e)}")




# ===== WEBSOCKET BROADCAST FOR REAL-TIME ALERTS =====
# Push new alerts to all connected WebSocket clients via Django Channels.
#
# IMPORTANT: InMemoryChannelLayer is process-local. poll_snort_logs runs
# in a SEPARATE process from Daphne (runserver), so direct channel_layer
# calls from here would never reach the WebSocket clients. Instead, we
# POST to an internal webhook on the Daphne server via HTTP.

def broadcast_alert_via_websocket(alert):
    """
    Broadcast a new alert to all connected WebSocket clients.

    Uses an HTTP POST to the running Daphne server's internal endpoint.
    This ensures the broadcast happens inside Daphne's process where
    the InMemoryChannelLayer can reach connected WebSocket consumers.

    Args:
        alert: Alert model instance that was just saved to the database
    """
    try:
        import requests
        from django.conf import settings as django_settings

        # Serialize alert data for WebSocket transmission
        alert_data = {
            'id': alert.id,
            'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
            'src_ip': alert.src_ip,
            'src_port': alert.src_port,
            'dest_ip': alert.dest_ip,
            'dest_port': alert.dest_port,
            'protocol': alert.protocol,
            'sid': alert.sid,
            'message': alert.message,
            'classification': alert.classification,
            'priority': alert.priority,
            'threat_level': alert.threat_level,
            'ml_processed': alert.ml_processed,
            'ml_threat_score': alert.ml_threat_score,
            'ml_classification': alert.ml_classification,
        }

        # POST to the Daphne server's internal broadcast endpoint
        response = requests.post(
            'http://127.0.0.1:8000/api/alerts/ws-broadcast/',
            json={'alert': alert_data},
            headers={'X-Internal-Key': django_settings.SECRET_KEY[:16]},
            timeout=3,
        )

        if response.status_code == 200:
            logger.debug(f'[WebSocket] Broadcast alert {alert.id} via HTTP webhook')
        else:
            logger.warning(f'[WebSocket] HTTP broadcast returned {response.status_code}: {response.text}')

    except Exception as e:
        # Never let WebSocket errors break the ingestion pipeline
        logger.warning(f'[WebSocket] Failed to broadcast alert {alert.id}: {e}')



# ===== ML MODEL INITIALIZATION =====
# Lazy-load ML threat analyzer on first use
_threat_analyzer = None

def get_threat_analyzer():
    # Load threat analyzer on first call (lazy initialization)
    global _threat_analyzer
    if _threat_analyzer is None:
        try:
            models_dir = str(Path(settings.BASE_DIR) / 'trained_models')

            # Model selection priority:
            # 1) settings.ML_MODEL_NAME (if defined)
            # 2) env var THREATEYE_ML_MODEL_NAME
            # 3) default: random_forest_simplified (CIC-IDS2017-trained baseline)
            model_name = (
                getattr(settings, 'ML_MODEL_NAME', None)
                or os.getenv('THREATEYE_ML_MODEL_NAME')
                or 'random_forest_simplified'
            )

            _threat_analyzer = ThreatAnalyzer(model_name=model_name, models_dir=models_dir)
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
        
        # Alert enriched with ML analysis (silent)
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


def ingest_snort_packet_logs(log_dir, max_packets=None, enable_ml=True, enable_email=True, enable_websocket=True):
    # Parse PCAP files, extract IPv4 packets, validate and store as alerts
    log_dir_path = Path(log_dir)
    if not log_dir_path.exists() or not log_dir_path.is_dir():
        return {'inserted': 0, 'processed_packets': 0, 'failed_packets': 0}

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
                        # Enrich alert with ML analysis (if enabled)
                        if enable_ml:
                            enrich_alert_with_ml(alert)
                        # Send email notification for MEDIUM and HIGH alerts (if enabled)
                        if enable_email:
                            send_alert_notification(alert)
                        # Broadcast to all connected WebSocket clients (if enabled)
                        if enable_websocket:
                            broadcast_alert_via_websocket(alert)
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



# ===== BATCH PROCESSING HELPERS =====

BATCH_SIZE = 500  # Number of alerts to process per batch


def _process_alert_batch(alert_objects, enable_ml=True, enable_email=True, enable_websocket=True):
    """
    Process a batch of Alert objects efficiently:
      0. DROP alerts from permanently blocked IPs (they can't attack anymore)
      1. Bulk insert into DB (skip duplicates)
      2. Batch ML enrichment
      3. WebSocket batch_complete signal
      4. Batch prevention (medium/high only)
      5. Single email digest per batch
    
    Args:
        alert_objects: List of Alert objects to process
        enable_ml: Run ML enrichment on alerts (default True)
        enable_email: Send email notifications (default True)
        enable_websocket: Broadcast WebSocket updates (default True)
    """
    if not alert_objects:
        return 0

    # ---- STEP 0: Drop alerts from permanently blocked IPs ----
    # (BlockedIP model not yet implemented - skip this step for now)
    # from .models import BlockedIP
    # blocked_ips = set(
    #     BlockedIP.objects.filter(
    #         block_type=BlockedIP.BLOCK_PERMANENT,
    #         is_active=True,
    #     ).values_list('ip_address', flat=True)
    # )
    # 
    # if blocked_ips:
    #     before = len(alert_objects)
    #     alert_objects = [a for a in alert_objects if a.src_ip not in blocked_ips]
    #     dropped = before - len(alert_objects)
    #     if dropped > 0:
    #         logger.info(f'[Prevention] Dropped {dropped} alerts from {len(blocked_ips)} permanently blocked IP(s)')
    # 
    # if not alert_objects:
    #     return 0

    # ---- STEP 1: Bulk insert, skip duplicates ----
    Alert.objects.bulk_create(
        alert_objects,
        ignore_conflicts=True,
        batch_size=500,
    )

    # Re-fetch inserted alerts (MySQL ignore_conflicts doesn't set IDs)
    hashes = [a.event_hash for a in alert_objects]
    saved_alerts = list(
        Alert.objects.filter(event_hash__in=hashes, ml_processed=False)
        .only('id', 'src_ip', 'dest_ip', 'src_port', 'dest_port',
              'protocol', 'sid', 'message', 'threat_level', 'priority',
              'event_hash', 'ml_processed')
    )

    if not saved_alerts:
        return 0

    count = len(saved_alerts)

    # ---- STEP 2: Batch ML enrichment ----
    if enable_ml:
        try:
            analyzer = get_threat_analyzer()
            if analyzer:
                ml_updates = []
                for alert in saved_alerts:
                    try:
                        result = analyzer.analyze_alert(alert)
                        if result['error'] is None:
                            alert.ml_processed = True
                            alert.ml_threat_score = result['confidence']
                            alert.ml_classification = 'attack' if result['threat_class'] == 1 else 'benign'
                            alert.ml_features = result.get('features_extracted', 0)
                            ml_updates.append(alert)
                    except Exception:
                        pass

                if ml_updates:
                    Alert.objects.bulk_update(
                        ml_updates,
                        ['ml_processed', 'ml_threat_score', 'ml_classification', 'ml_features'],
                        batch_size=500,
                    )
        except Exception as e:
            logger.warning(f'[Batch ML] Error: {e}')

    # ---- STEP 3: Broadcast batch_complete signal to frontend ----
    # Tells the frontend to re-fetch from the API (not individual alerts)
    if enable_websocket:
        try:
            import requests
            from django.conf import settings as django_settings
            webhook_url = 'http://127.0.0.1:8000/api/alerts/ws-broadcast/'
            latest = saved_alerts[-1]

            response = requests.post(webhook_url, json={
                'type': 'alert.batch',
                'count': count,
                'latest': {
                    'id': latest.id,
                    'src_ip': latest.src_ip,
                    'dest_ip': latest.dest_ip,
                    'message': latest.message[:200],
                    'threat_level': latest.threat_level,
                },
            }, headers={'X-Internal-Key': django_settings.SECRET_KEY[:16]}, timeout=3)

            if response.status_code == 200:
                logger.debug(f'[WebSocket] Broadcast batch {count} via HTTP webhook')
            else:
                logger.warning(f'[WebSocket] HTTP batch broadcast returned {response.status_code}: {response.text}')
        except Exception as e:
            logger.warning(f'[Batch WS] Broadcast failed: {e}')

    # ---- STEP 4: Prevention (medium/high only) ----
    # (prevention module not yet implemented - skip this step for now)
    # try:
    #     from .prevention import apply_prevention_action
    #     severe = [a for a in saved_alerts if a.threat_level in (Alert.THREAT_MEDIUM, Alert.THREAT_HIGH)]
    #     for alert in severe:
    #         apply_prevention_action(alert)
    # except Exception as e:
    #     logger.warning(f'[Batch Prevention] Error: {e}')

    # ---- STEP 5: Email notifications ----
    # Send email notifications for MEDIUM and HIGH threats (rate limited per severity)
    if enable_email:
        for alert in saved_alerts:
            try:
                send_alert_notification(alert)
            except Exception as e:
                logger.error(f'[Batch Email] Error sending notification for alert {alert.id}: {e}')

    return count


# ===== OPTIMIZED BATCH INGESTION =====

def ingest_snort_logs(log_dir, max_lines=None, enable_ml=True, enable_email=True, enable_websocket=True):
    """
    Parse FAST format alert logs, validate, deduplicate via event_hash,
    and store alerts using efficient batch processing.
    
    Args:
        log_dir: Path to Snort log directory
        max_lines: Max lines to process (None = all)
        enable_ml: Run ML enrichment on alerts (default True)
        enable_email: Send email notifications (default True)
        enable_websocket: Broadcast WebSocket updates (default True)
    """
    log_dir_path = Path(log_dir)
    if not log_dir_path.exists() or not log_dir_path.is_dir():
        logger.warning(f'Log directory does not exist: {log_dir}')
        return {'inserted': 0, 'processed_lines': 0, 'failed_lines': 0}

    # Find all alert log files (filename contains "alert")
    log_files = sorted(
        [p for p in log_dir_path.rglob('*alert*') if p.is_file() and p.suffix != '.gz' and not p.name.startswith('.')],
        key=lambda p: p.name,
    )

    inserted = 0
    processed_lines = 0
    failed_lines = 0
    batch = []  # Accumulate Alert objects for batch processing

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

                    # Append to batch instead of inserting one-by-one
                    batch.append(Alert(
                        **cleaned_data,
                        raw_line=line.strip(),
                        event_hash=event_hash,
                    ))

                    # Process batch when it reaches BATCH_SIZE
                    if len(batch) >= BATCH_SIZE:
                        inserted += _process_alert_batch(batch, enable_ml=enable_ml, enable_email=enable_email, enable_websocket=enable_websocket)
                        batch = []

                state.offset = handle.tell()

            # Save progress (file offset + inode) for resume on restart
            LogIngestionState.objects.update_or_create(
                file_path=file_path,
                defaults={'inode': state.inode, 'offset': state.offset}
            )
        except Exception:
            logger.exception('Error while ingesting alert log file %s', log_file)
            continue

    # Process any remaining alerts in the final partial batch
    if batch:
        inserted += _process_alert_batch(batch, enable_ml=enable_ml, enable_email=enable_email, enable_websocket=enable_websocket)

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

            total_inserted = text_result.get('inserted', 0) + packet_result.get('inserted', 0)
            total_processed = text_result.get('processed_lines', 0) + packet_result.get('processed_packets', 0)
            total_failed = text_result.get('failed_lines', 0) + packet_result.get('failed_packets', 0)

            if total_inserted > 0 or total_failed > 0:
                logger.info(
                    f'[{datetime.now().strftime("%H:%M:%S")}] '
                    f'Detected: {total_processed} | Inserted: {total_inserted} | Failed: {total_failed}'
                )

            # Cleanup expired temporary blocks
            try:
                from .prevention import cleanup_expired_blocks
                cleanup_expired_blocks()
            except Exception:
                pass

        except Exception:
            logger.exception('Error in polling loop iteration')

        time.sleep(interval_seconds)
