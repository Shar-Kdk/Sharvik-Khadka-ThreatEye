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


logger = logging.getLogger(__name__)


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
    if ':' not in endpoint:
        return endpoint, None

    ip_part, port_part = endpoint.rsplit(':', 1)
    if port_part.isdigit():
        return ip_part, int(port_part)

    return endpoint, None


def map_priority_to_threat_level(priority):
    if priority == 1:
        return Alert.THREAT_HIGH
    if priority == 2:
        return Alert.THREAT_MEDIUM
    if priority == 3:
        return Alert.THREAT_SAFE
    return Alert.THREAT_SAFE


def parse_snort_fast_line(line):
    match = FAST_ALERT_PATTERN.match(line.strip())
    if not match:
        return None

    parts = match.groupdict()

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
        return None

    timestamp_obj = timezone.make_aware(timestamp_obj, timezone.get_current_timezone())
    src_ip, src_port = parse_endpoint(parts['src'])
    dest_ip, dest_port = parse_endpoint(parts['dest'])
    priority = int(parts['priority'])

    return {
        'timestamp': timestamp_obj,
        'src_ip': src_ip,
        'src_port': src_port,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'protocol': parts['protocol'],
        'sid': parts['sid'],
        'message': parts['message'],
        'classification': parts['classification'],
        'priority': priority,
        'threat_level': map_priority_to_threat_level(priority),
    }


def _get_file_inode(log_file):
    stat_result = log_file.stat()
    return str(getattr(stat_result, 'st_ino', ''))


def _get_protocol_name(protocol_number):
    if protocol_number == 6:
        return 'TCP'
    if protocol_number == 17:
        return 'UDP'
    if protocol_number == 1:
        return 'ICMP'
    return f'IP-{protocol_number}'


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
            file_path = str(log_file.resolve())
            inode = _get_file_inode(log_file)
            state, _ = LogIngestionState.objects.get_or_create(file_path=file_path)

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

                    hash_source = f"{file_path}:{ts_sec}:{ts_usec}:{parsed_packet['src_ip']}:{parsed_packet['dest_ip']}:{incl_len}"
                    event_hash = hashlib.sha256(hash_source.encode('utf-8')).hexdigest()

                    try:
                        Alert.objects.create(
                            timestamp=timestamp,
                            src_ip=parsed_packet['src_ip'],
                            src_port=parsed_packet['src_port'],
                            dest_ip=parsed_packet['dest_ip'],
                            dest_port=parsed_packet['dest_port'],
                            protocol=parsed_packet['protocol'],
                            sid='packet_capture',
                            message='Real-time packet captured from snort.log',
                            classification='Packet Log',
                            priority=3,
                            threat_level=Alert.THREAT_SAFE,
                            raw_line=f"pcap:{file_path}:{ts_sec}.{ts_usec}:{parsed_packet['src_ip']}->{parsed_packet['dest_ip']}",
                            event_hash=event_hash,
                        )
                        inserted += 1
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
    log_dir_path = Path(log_dir)
    if not log_dir_path.exists() or not log_dir_path.is_dir():
        logger.warning(f'Log directory does not exist: {log_dir}')
        return {'inserted': 0, 'processed_lines': 0, 'failed_lines': 0}

    # Recursively find all alert files (snort.alert.fast* or alert_* patterns)
    # Supports structure: real_logs/<year>/<month>/<day>/alert_*
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
            file_path = str(log_file.resolve())
            inode = _get_file_inode(log_file)
            state, _ = LogIngestionState.objects.get_or_create(file_path=file_path)

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
                    parsed = parse_snort_fast_line(line)
                    if not parsed:
                        continue

                    hash_source = f'{file_path}:{line_start}:{line.strip()}'
                    event_hash = hashlib.sha256(hash_source.encode('utf-8')).hexdigest()

                    try:
                        Alert.objects.create(
                            **parsed,
                            raw_line=line.strip(),
                            event_hash=event_hash,
                        )
                        inserted += 1
                    except IntegrityError:
                        continue
                    except Exception:
                        failed_lines += 1
                        logger.exception('Failed to store parsed alert line from %s', file_path)
                        continue

                state.offset = handle.tell()

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


def run_polling_loop(log_dir, interval_seconds=3):
    while True:
        try:
            text_result = ingest_snort_logs(log_dir)
            packet_result = ingest_snort_packet_logs(log_dir)

            logger.info(
                'Snort ingest cycle complete: text=%s packet=%s',
                text_result,
                packet_result,
            )
        except Exception:
            logger.exception('Unhandled error in snort polling loop')

        time.sleep(max(1, interval_seconds))
