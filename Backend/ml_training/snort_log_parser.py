"""
Snort Log Parser - Extracts training data from real Snort FAST format logs.

This parser:
1. Reads all .txt log files from ./real_logs/ (shared with Snort VM)
2. Parses FAST format: "timestamp [**] [SID:rev] message [**] [classification] [priority] {protocol} src_ip:port -> dest_ip:port"
3. Labels threats based on Snort priority and classification
4. Extracts features using SimplifiedFeatureExtractor
5. Returns: numpy arrays (X, y) ready for model training

Format example:
04/21-02:48:19.661099  [**] [1:1000008:1] TCP SYN Flood Detected [**] [Classification: Attempted Denial of Service] [Priority: 1] {TCP} 192.168.73.130:39894 -> 192.168.73.129:929
"""

import os
import re
import logging
from typing import Tuple, List, Dict
from pathlib import Path
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)


class SnortLogParser:
    """Parse real Snort FAST format logs from ./real_logs/ directory."""
    
    # Regex to parse FAST format lines
    FAST_LOG_PATTERN = re.compile(
        r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'  # timestamp
        r'\[\*\*\]\s+'
        r'\[(\d+):(\d+):(\d+)\]\s+'  # SID:rev:protocol_id
        r'([^\[]+?)\s+\[\*\*\]\s+'  # message
        r'\[Classification:\s*([^\]]+)\]\s+'  # classification
        r'\[Priority:\s*(\d+)\]\s+'  # priority
        r'\{([A-Z]+)\}\s+'  # protocol
        r'([0-9.]+):(\d+)\s+->\s+'  # src_ip:src_port
        r'([0-9.]+):(\d+)'  # dest_ip:dest_port
    )
    
    # Classification labels for threat detection
    # Low-risk classifications
    LOW_RISK_KEYWORDS = [
        'non-standard protocol',
        'protocol-command decode',
        'shellcode detect',
        'string detect',
        'suspicious filename detect',
        'suspicious login attempt',
        'rpc-portmap decode',
        'icmp unreachable',
        'icmp ping',
        'tcp connection attempt',
        'tool use',
        'unknown traffic',
        'potentially unwanted traffic',
        'generic protocol command decode'
    ]
    
    # High-risk classifications
    HIGH_RISK_KEYWORDS = [
        'attempted denial of service',
        'attempted user privilege gain',
        'attempted information leak',
        'potentially unwanted traffic',
        'network trojan',
        'trojan activity',
        'bad traffic',
        'suspicious traffic',
        'web application attack',
        'network scan',
        'backdoor',
        'exploit'
    ]
    
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            # Look for logs in multiple possible locations
            candidates = [
                Path("../../real_logs"),                                          # From ml_training/
                Path("../real_logs"),                                            # From Backend/
                Path("./real_logs"),                                             # From project root
                Path(__file__).parent.parent.parent / "real_logs",              # Absolute from script
            ]
            for candidate in candidates:
                abs_path = Path(candidate).resolve()
                if abs_path.exists():
                    log_dir = str(abs_path)
                    logger.info(f"Found real_logs at: {log_dir}")
                    break
            
            if log_dir is None:
                raise ValueError(f"real_logs not found. Tried: {[str(Path(c).resolve()) for c in candidates]}")
        
        self.log_dir = Path(log_dir)
        self.logs = []
        self.failed_parses = 0
        
    def get_label_from_priority(self, priority: str, classification: str) -> int:
        """
        Determine label (0=benign, 1=threat) from Snort priority and classification.
        
        Priority in Snort:
        - 1 = High (indicative of suspicious network traffic or activity)
        - 2 = Medium (indicative of unusual network traffic)
        - 3 = Low (indicative of policy violation)
        
        Classification keywords help further refine:
        - Low-risk = benign (0)
        - High-risk = threat (1)
        - Priority 1 = threat (1) unless classified as low-risk
        - Priority 2-3 = depends on classification
        """
        try:
            priority_int = int(priority)
        except:
            return 0  # Default to benign if parsing fails
        
        classification_lower = classification.lower()
        
        # Check high-risk keywords
        for keyword in self.HIGH_RISK_KEYWORDS:
            if keyword in classification_lower:
                return 1  # Threat
        
        # Check low-risk keywords
        for keyword in self.LOW_RISK_KEYWORDS:
            if keyword in classification_lower:
                return 0  # Benign
        
        # Default based on priority
        if priority_int == 1:
            return 1  # High priority = likely threat
        elif priority_int == 2:
            return 1  # Medium is often suspicious
        else:
            return 0  # Low priority = likely benign
    
    def parse_fast_line(self, line: str) -> Dict or None:
        """Parse a single FAST format Snort log line."""
        match = self.FAST_LOG_PATTERN.search(line)
        if not match:
            self.failed_parses += 1
            return None
        
        groups = match.groups()
        return {
            'timestamp': groups[0],
            'sid': groups[1],
            'sid_rev': groups[2],
            'sid_proto': groups[3],
            'message': groups[4].strip(),
            'classification': groups[5].strip(),
            'priority': groups[6],
            'protocol': groups[7],
            'src_ip': groups[8],
            'src_port': int(groups[9]),
            'dest_ip': groups[10],
            'dest_port': int(groups[11]),
        }
    
    def collect_from_directory(self) -> List[Dict]:
        """Recursively collect all log files from real_logs directory."""
        log_files = []
        
        if not self.log_dir.exists():
            logger.warning(f"Log directory not found: {self.log_dir}")
            return []
        
        # Recursively find all text files
        for root, dirs, files in os.walk(str(self.log_dir)):
            for file in files:
                if file.startswith('alert_') or file.endswith('.txt'):
                    log_files.append(os.path.join(root, file))
        
        logger.info(f"Found {len(log_files)} log files to process")
        return sorted(log_files)
    
    def parse_logs(self) -> Tuple[List[Dict], int, int]:
        """
        Parse all logs from real_logs directory.
        
        Returns:
            (parsed_logs, total_lines, failed_parses)
        """
        log_files = self.collect_from_directory()
        total_lines = 0
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        
                        parsed = self.parse_fast_line(line)
                        if parsed:
                            # Determine label
                            label = self.get_label_from_priority(
                                parsed['priority'],
                                parsed['classification']
                            )
                            parsed['label'] = label
                            self.logs.append(parsed)
                        
                        total_lines += 1
                        
                        if total_lines % 10000 == 0:
                            logger.info(f"Parsed {total_lines} lines, {len(self.logs)} valid logs")
            
            except Exception as e:
                logger.error(f"Error reading {log_file}: {e}")
        
        logger.info(f"Total lines: {total_lines}, Parsed: {len(self.logs)}, Failed: {self.failed_parses}")
        return self.logs, total_lines, self.failed_parses
    
    def get_label_distribution(self) -> Dict[str, int]:
        """Get distribution of benign (0) vs threat (1) labels."""
        if not self.logs:
            return {}
        
        benign = sum(1 for log in self.logs if log['label'] == 0)
        threat = sum(1 for log in self.logs if log['label'] == 1)
        
        return {
            'benign': benign,
            'threat': threat,
            'total': len(self.logs),
            'benign_percent': (benign / len(self.logs) * 100) if self.logs else 0,
            'threat_percent': (threat / len(self.logs) * 100) if self.logs else 0,
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test parser
    parser = SnortLogParser(log_dir="./real_logs")
    logs, total, failed = parser.parse_logs()
    
    print(f"\n=== SNORT LOG PARSING RESULTS ===")
    print(f"Total lines processed: {total}")
    print(f"Successfully parsed: {len(logs)}")
    print(f"Failed parses: {failed}")
    print(f"\nLabel distribution:")
    dist = parser.get_label_distribution()
    for key, val in dist.items():
        if isinstance(val, float):
            print(f"  {key}: {val:.2f}%")
        else:
            print(f"  {key}: {val}")
