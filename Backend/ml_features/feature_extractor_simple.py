"""
Simplified feature extractor for Snort alerts.
Extracts 12 essential features directly from Snort alert data.
Training time: ~5 minutes (vs 2 hours for CIC-IDS17)
"""

import numpy as np
import ipaddress
import re
from typing import List, Dict, Tuple


class SimplifiedFeatureExtractor:
    """
    Extract simplified features from Snort alerts.
    Features are designed to capture attack signatures from raw Snort data.
    """

    # Feature names (in order)
    FEATURE_NAMES = [
        'dest_port',
        'src_port',
        'protocol',
        'threat_level',
        'sid_normalized',
        'fin_flag',
        'rst_flag',
        'psh_flag',
        'ack_flag',
        'urg_flag',
        'src_ip_internal',
        'dest_ip_internal'
    ]

    # Port ranges
    PRIVILEGED_PORT_THRESHOLD = 1024
    EPHEMERAL_PORT_MIN = 49152

    # Protocol mappings
    PROTOCOL_MAP = {
        'tcp': 1,
        'udp': 2,
        'icmp': 3,
    }

    # Threat level mappings
    THREAT_LEVEL_MAP = {
        'safe': 1,
        'medium': 2,
        'high': 3,
    }

    # Known Snort SIDs for normalization range
    MAX_SID_FOR_NORMALIZATION = 1000000  # Approximate max SID value

    @staticmethod
    def _is_internal_ip(ip_str: str) -> int:
        """
        Check if IP is in private/internal range.
        Returns 1 for internal, 0 for external.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            is_private = ip.is_private or ip.is_loopback
            return 1 if is_private else 0
        except (ValueError, TypeError):
            return 0

    @staticmethod
    def _extract_tcp_flags(message: str) -> Tuple[int, int, int, int, int]:
        """
        Extract TCP flags from Snort message.
        Returns: (FIN, RST, PSH, ACK, URG) each as 0 or 1
        """
        message_lower = message.lower()

        # Look for flag indicators in message
        fin = 1 if 'fin' in message_lower else 0
        rst = 1 if 'rst' in message_lower or 'reset' in message_lower else 0
        psh = 1 if 'psh' in message_lower or 'push' in message_lower else 0
        ack = 1 if 'ack' in message_lower else 0
        urg = 1 if 'urg' in message_lower or 'urgent' in message_lower else 0

        return fin, rst, psh, ack, urg

    @staticmethod
    def _encode_protocol(protocol: str) -> int:
        """Encode protocol string to numeric value."""
        protocol_lower = protocol.lower().strip()
        return SimplifiedFeatureExtractor.PROTOCOL_MAP.get(protocol_lower, 0)

    @staticmethod
    def _encode_threat_level(threat_level: str) -> int:
        """Encode threat level string to numeric value."""
        threat_lower = threat_level.lower().strip()
        return SimplifiedFeatureExtractor.THREAT_LEVEL_MAP.get(threat_lower, 1)

    @staticmethod
    def _normalize_sid(sid: str) -> float:
        """Normalize SID to 0-1 range."""
        try:
            sid_int = int(sid)
            normalized = min(sid_int / SimplifiedFeatureExtractor.MAX_SID_FOR_NORMALIZATION, 1.0)
            return normalized
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def _normalize_port(port: int) -> float:
        """Normalize port number to 0-1 range."""
        if port is None:
            return 0.0
        # Max port is 65535
        return min(port / 65535.0, 1.0)

    def extract_features(self, alert: Dict) -> np.ndarray:
        """
        Extract 12 simplified features from a single Snort alert.

        Args:
            alert: Dictionary with keys:
                - dest_port: int or None
                - src_port: int or None
                - protocol: str (tcp/udp/icmp)
                - threat_level: str (safe/medium/high)
                - sid: str
                - message: str
                - src_ip: str
                - dest_ip: str

        Returns:
            numpy array of shape (12,) with normalized features
        """
        features = []

        # 1. Destination port (normalized)
        dest_port = alert.get('dest_port')
        features.append(self._normalize_port(dest_port))

        # 2. Source port (normalized)
        src_port = alert.get('src_port')
        features.append(self._normalize_port(src_port))

        # 3. Protocol (encoded)
        protocol = alert.get('protocol', '')
        features.append(self._encode_protocol(protocol))

        # 4. Threat level (encoded)
        threat_level = alert.get('threat_level', 'safe')
        features.append(self._encode_threat_level(threat_level))

        # 5. SID (normalized)
        sid = alert.get('sid', '0')
        features.append(self._normalize_sid(sid))

        # 6-10. TCP flags (FIN, RST, PSH, ACK, URG)
        message = alert.get('message', '')
        fin, rst, psh, ack, urg = self._extract_tcp_flags(message)
        features.extend([fin, rst, psh, ack, urg])

        # 11. Source IP is internal
        src_ip = alert.get('src_ip', '')
        features.append(self._is_internal_ip(src_ip))

        # 12. Destination IP is internal
        dest_ip = alert.get('dest_ip', '')
        features.append(self._is_internal_ip(dest_ip))

        return np.array(features, dtype=np.float32)

    def extract_features_batch(self, alerts: List[Dict]) -> np.ndarray:
        """
        Extract features from multiple alerts.

        Args:
            alerts: List of alert dictionaries

        Returns:
            numpy array of shape (n_alerts, 12) with normalized features
        """
        features_list = []
        for alert in alerts:
            features = self.extract_features(alert)
            features_list.append(features)

        return np.array(features_list, dtype=np.float32)

    @staticmethod
    def get_feature_names() -> List[str]:
        """Return list of feature names."""
        return SimplifiedFeatureExtractor.FEATURE_NAMES
