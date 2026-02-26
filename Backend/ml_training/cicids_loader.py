"""
CICIDS2017 Dataset Loader - Prepares CICIDS2017 data for baseline model training.

CICIDS2017 has 84 features + Label column. We need to:
1. Load all 8 CSV files from ./dataset/
2. Map features to our 12-feature format (compatible with SimplifiedFeatureExtractor)
3. Label benign (0) vs attack (1)
4. Handle class imbalance

CICIDS2017 structure:
- Columns: Flow Duration, Total Fwd Packets, Total Bwd Packets, ..., Label
- Label: 'BENIGN' or attack type (e.g., 'DoS GoldenEye', 'Port Scan')
"""

import pandas as pd
import numpy as np
import logging
import os
from pathlib import Path
from typing import Tuple, List, Dict

logger = logging.getLogger(__name__)


class CICIDS2017Loader:
    """Load and prepare CICIDS2017 dataset for training."""
    
    # CICIDS2017 CSV files in ./dataset directory
    CSV_FILES = [
        'Monday-WorkingHours.pcap_ISCX.csv',
        'Tuesday-WorkingHours.pcap_ISCX.csv',
        'Wednesday-workingHours.pcap_ISCX.csv',
        'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
        'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    ]
    
    # Maps CICIDS2017 columns to our 12 features
    # Our 12 features: [dest_port, src_port, protocol, threat_level, sid_normalized, fin_flag, rst_flag, psh_flag, ack_flag, urg_flag, src_ip_internal, dest_ip_internal]
    FEATURE_MAPPING = {
        'dest_port': ['Destination Port'],
        'src_port': ['Source Port'],
        'protocol': ['Protocol'],
        'threat_level': [],  # Will compute from label
        'sid_normalized': ['Flow ID'],  # Use flow ID as proxy for signature
        'fin_flag': ['FIN Flag Count'],
        'rst_flag': ['RST Flag Count'],
        'psh_flag': ['PSH Flag Count'],
        'ack_flag': ['ACK Flag Count'],
        'urg_flag': ['URG Flag Count'],
        'src_ip_internal': [],  # Will compute if source IP is internal
        'dest_ip_internal': [],  # Will compute if dest IP is internal
    }
    
    FEATURE_NAMES = [
        'dest_port', 'src_port', 'protocol', 'threat_level',
        'sid_normalized', 'fin_flag', 'rst_flag', 'psh_flag',
        'ack_flag', 'urg_flag', 'src_ip_internal', 'dest_ip_internal'
    ]
    
    # Internal IP ranges (RFC 1918)
    INTERNAL_IP_RANGES = [
        (0, 0),  # Will check actual private ranges
    ]
    
    def __init__(self, dataset_dir: str = None):
        if dataset_dir is None:
            # Look for dataset in multiple possible locations
            candidates = [
                Path("../../dataset"),                                           # From ml_training/
                Path("../dataset"),                                             # From Backend/
                Path("./dataset"),                                              # From project root
                Path(__file__).parent.parent.parent / "dataset",               # Absolute from script
            ]
            for candidate in candidates:
                abs_path = Path(candidate).resolve()
                if abs_path.exists():
                    dataset_dir = str(abs_path)
                    logging.info(f"Found dataset at: {dataset_dir}")
                    break
            
            if dataset_dir is None:
                raise ValueError(f"Dataset not found. Tried: {[str(Path(c).resolve()) for c in candidates]}")
        
        self.dataset_dir = Path(dataset_dir)
        self.df = None
        
    def is_private_ip(self, ip_str: str) -> bool:
        """Check if IP address is private (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."""
        try:
            parts = list(map(int, ip_str.split('.')))
            if not all(0 <= p <= 255 for p in parts):
                return False
            
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            
            return False
        except:
            return False
    
    def load_all_csvs(self) -> pd.DataFrame:
        """Load all CICIDS2017 CSV files and concatenate."""
        dfs = []
        
        # Try to find label column from first file
        first_file = self.dataset_dir / self.CSV_FILES[0]
        if first_file.exists():
            df_sample = pd.read_csv(first_file, nrows=1)
            for col in df_sample.columns:
                if 'label' in col.lower():
                    logger.info(f"Detected label column: '{col}' from {self.CSV_FILES[0]}")
                    break
        
        for csv_file in self.CSV_FILES:
            file_path = self.dataset_dir / csv_file
            
            if not file_path.exists():
                logger.warning(f"CSV file not found: {file_path}")
                continue
            
            try:
                logger.info(f"Loading {csv_file}...")
                df = pd.read_csv(file_path)
                logger.info(f"  Shape: {df.shape}, Columns: {df.shape[1]}")
                dfs.append(df)
            except Exception as e:
                logger.error(f"Error loading {csv_file}: {e}")
        
        if not dfs:
            raise ValueError("No CSV files loaded successfully")
        
        # Concatenate all DataFrames
        combined_df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Combined dataset shape: {combined_df.shape}")
        
        return combined_df
    
    def get_label_from_cicids(self, label: str) -> int:
        """Convert CICIDS2017 label string to binary (0=benign, 1=attack)."""
        if str(label).strip().upper() == 'BENIGN':
            return 0
        else:
            return 1  # Any attack type = 1
    
    def map_protocol_to_numeric(self, protocol_val) -> int:
        """Map protocol values to numeric."""
        try:
            protocol_int = int(protocol_val)
            if protocol_int == 6:
                return 1  # TCP
            elif protocol_int == 17:
                return 2  # UDP
            elif protocol_int == 1:
                return 3  # ICMP
            else:
                return 4  # Other
        except:
            return 4
    
    def hash_to_normalized_sid(self, flow_id: str) -> float:
        """Convert Flow ID to normalized SID-like value."""
        try:
            # Use first 8 hex chars, convert to int, normalize to 0-1
            flow_int = int(str(flow_id).split('-')[0][:8], 16) if isinstance(flow_id, str) else hash(str(flow_id))
            return float(flow_int % 1000) / 1000.0
        except:
            return 0.5
    
    def prepare_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extract our 12 features from CICIDS2017 data.
        
        Returns:
            (X: feature matrix [n_samples, 12], y: labels [n_samples])
        """
        features_list = []
        labels = []
        
        logger.info("Extracting features from CICIDS2017...")
        
        # CICIDS2017 label column name (with leading space!)
        label_col = ' Label'
        
        # Verify column exists
        if label_col not in df.columns:
            logger.error(f"Label column '{label_col}' not found! Available: {list(df.columns[:5])}")
            raise ValueError(f"Label column '{label_col}' not in dataset")
        
        logger.info(f"Using label column: '{label_col}'")
        
        for idx, row in df.iterrows():
            try:
                # Extract label from correct column
                label_value = row[label_col]
                label = self.get_label_from_cicids(label_value)
                labels.append(label)
                
                # Extract 12 features
                feature_vector = []
                
                # 1. dest_port
                feature_vector.append(int(row.get('Destination Port', 0)))
                
                # 2. src_port
                feature_vector.append(int(row.get('Source Port', 0)))
                
                # 3. protocol (map to numeric)
                feature_vector.append(self.map_protocol_to_numeric(row.get('Protocol', 0)))
                
                # 4. threat_level (0=benign, 1=threat)
                feature_vector.append(label)
                
                # 5. sid_normalized
                feature_vector.append(self.hash_to_normalized_sid(row.get('Flow ID', '')))
                
                # 6-10. TCP Flags
                feature_vector.append(int(row.get('FIN Flag Count', 0)))  # fin_flag
                feature_vector.append(int(row.get('RST Flag Count', 0)))  # rst_flag
                feature_vector.append(int(row.get('PSH Flag Count', 0)))  # psh_flag
                feature_vector.append(int(row.get('ACK Flag Count', 0)))  # ack_flag
                feature_vector.append(int(row.get('URG Flag Count', 0)))  # urg_flag
                
                # 11-12. Internal IPs (parse from source/dest)
                # Note: CICIDS2017 might not have IP addresses; use 0 if not found
                src_internal = 1 if self.is_private_ip(str(row.get('Source IP', ''))) else 0
                dest_internal = 1 if self.is_private_ip(str(row.get('Destination IP', ''))) else 0
                feature_vector.append(src_internal)
                feature_vector.append(dest_internal)
                
                features_list.append(feature_vector)
                
                if (idx + 1) % 50000 == 0:
                    logger.info(f"Processed {idx + 1} rows...")
            
            except Exception as e:
                logger.debug(f"Error processing row {idx}: {e}")
                continue
        
        X = np.array(features_list, dtype=np.float32)
        y = np.array(labels, dtype=np.int32)
        
        logger.info(f"Features shape: {X.shape}, Labels shape: {y.shape}")
        logger.info(f"Label distribution: {np.bincount(y)}")
        
        return X, y
    
    def load_and_prepare(self) -> Tuple[np.ndarray, np.ndarray]:
        """Load all CICIDS2017 data and prepare features."""
        df = self.load_all_csvs()
        X, y = self.prepare_features(df)
        return X, y


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test loader
    loader = CICIDS2017Loader(dataset_dir="./dataset")
    X, y = loader.load_and_prepare()
    
    print(f"\n=== CICIDS2017 LOADING RESULTS ===")
    print(f"Feature matrix shape: {X.shape}")
    print(f"Labels shape: {y.shape}")
    print(f"Benign samples: {np.sum(y == 0)}")
    print(f"Attack samples: {np.sum(y == 1)}")
    print(f"Feature names: {loader.FEATURE_NAMES}")
