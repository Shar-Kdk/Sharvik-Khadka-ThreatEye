"""
Simplified feature extractor for Snort alerts.
Extracts 12 essential features directly from Snort alert data.
Training time: ~5 minutes (vs 2 hours for CIC-IDS17)
"""

import numpy as np
import ipaddress
import re
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)


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
    MAX_SID_FOR_NORMALIZATION = 100_000_000  # Approximate max SID value

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
        Defensive: Never raises exceptions, returns safe defaults on bad data

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
        try:
            if not isinstance(alert, dict):
                logger.warning(f"Extract_features received non-dict: {type(alert)}, returning safe defaults")
                return np.zeros(12, dtype=np.float32)
            
            features = []

            # Destination port (normalized)
            try:
                dest_port = alert.get('dest_port')
                features.append(self._normalize_port(dest_port))
            except Exception as e:
                logger.debug(f"Error extracting dest_port: {e}")
                features.append(0.0)

            # Source port (normalized)
            try:
                src_port = alert.get('src_port')
                features.append(self._normalize_port(src_port))
            except Exception as e:
                logger.debug(f"Error extracting src_port: {e}")
                features.append(0.0)

            # Protocol (encoded)
            try:
                protocol = alert.get('protocol', '')
                features.append(self._encode_protocol(protocol))
            except Exception as e:
                logger.debug(f"Error encoding protocol: {e}")
                features.append(0)

            # Threat level (encoded)
            try:
                threat_level = alert.get('threat_level', 'safe')
                features.append(self._encode_threat_level(threat_level))
            except Exception as e:
                logger.debug(f"Error encoding threat_level: {e}")
                features.append(1)

            # SID (normalized)
            try:
                sid = alert.get('sid', '0')
                features.append(self._normalize_sid(sid))
            except Exception as e:
                logger.debug(f"Error normalizing SID: {e}")
                features.append(0.0)

            # TCP flags (FIN, RST, PSH, ACK, URG)
            try:
                message = alert.get('message', '')
                fin, rst, psh, ack, urg = self._extract_tcp_flags(message)
                features.extend([fin, rst, psh, ack, urg])
            except Exception as e:
                logger.debug(f"Error extracting TCP flags: {e}")
                features.extend([0, 0, 0, 0, 0])

            # Source IP is internal
            try:
                src_ip = alert.get('src_ip', '')
                features.append(self._is_internal_ip(src_ip))
            except Exception as e:
                logger.debug(f"Error checking src_ip: {e}")
                features.append(0)

            # Destination IP is internal
            try:
                dest_ip = alert.get('dest_ip', '')
                features.append(self._is_internal_ip(dest_ip))
            except Exception as e:
                logger.debug(f"Error checking dest_ip: {e}")
                features.append(0)

            result = np.array(features, dtype=np.float32)
            
            if result.shape != (12,):
                logger.warning(f"Feature extraction resulted in shape {result.shape}, padding/trimming to (12,)")
                result_safe = np.zeros(12, dtype=np.float32)
                result_safe[:min(len(result), 12)] = result[:min(len(result), 12)]
                result = result_safe
            
            return result

        except Exception as e:
            logger.error(f"Unexpected error in extract_features: {e}, returning safe defaults")
            return np.zeros(12, dtype=np.float32)

    def extract_features_batch(self, alerts: List[Dict]) -> np.ndarray:
        """
        Extract features from multiple alerts.
        Defensive: Handles bad alerts gracefully without breaking pipeline

        Args:
            alerts: List of alert dictionaries

        Returns:
            numpy array of shape (n_alerts, 12) with normalized features
        """
        if not alerts:
            return np.zeros((0, 12), dtype=np.float32)
        
        if not isinstance(alerts, (list, tuple)):
            logger.warning(f"extract_features_batch received non-list: {type(alerts)}")
            return np.zeros((0, 12), dtype=np.float32)
        
        features_list = []
        error_count = 0
        
        for i, alert in enumerate(alerts):
            try:
                features = self.extract_features(alert)
                features_list.append(features)
            except Exception as e:
                error_count += 1
                logger.warning(f"Error extracting features from alert {i}: {e}, using safe defaults")
                features_list.append(np.zeros(12, dtype=np.float32))
        
        if error_count > 0:
            logger.warning(f"Batch extraction completed with {error_count}/{len(alerts)} errors")
        
        result = np.array(features_list, dtype=np.float32)
        
        if result.shape[1:] != (12,):
            logger.error(f"Batch result has unexpected shape {result.shape}, padding to correct shape")
            if len(result.shape) == 1:
                result = np.atleast_2d(result)
        
        return result

    @staticmethod
    def get_feature_names() -> List[str]:
        """Return list of feature names."""
        return SimplifiedFeatureExtractor.FEATURE_NAMES
