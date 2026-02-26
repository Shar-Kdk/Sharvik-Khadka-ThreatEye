"""
Complete ML Model Training Pipeline - 3 Phases

Phase 1: Train baseline RandomForest on CICIDS2017 (~1 hour compute)
Phase 2: Parse 160k real Snort logs and extract features (~30 minutes)
Phase 3: Fine-tune model with warm_start=True (~5 minutes compute)

This script implements transfer learning: start with generic dataset knowledge,
then adapt to user's specific network patterns.
"""

import numpy as np
import pandas as pd
import logging
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    accuracy_score, precision_score, recall_score, f1_score
)
import joblib

# Add backend path to imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from snort_log_parser import SnortLogParser
from cicids_loader import CICIDS2017Loader
from enhanced_features import EnhancedFeatureEngineer

logger = logging.getLogger(__name__)


class MLTrainingPipeline:
    """Complete training pipeline with 3 phases."""
    
    def __init__(self, output_dir: str = "./trained_models"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.baseline_model = None
        self.finetuned_model = None
        
        self.baseline_metrics = {}
        self.finetuned_metrics = {}
    
    def log_section(self, title: str):
        """Pretty print section headers."""
        width = 60
        logger.info("=" * width)
        logger.info(f" {title:^{width-2}} ")
        logger.info("=" * width)
    
    def phase_1_train_baseline(self, dataset_dir: str = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Phase 1: Train RandomForest on CICIDS2017
        
        Returns: (X_train, y_train) for later fine-tuning
        """
        self.log_section("PHASE 1: BASELINE TRAINING (CICIDS2017)")
        
        logger.info("\n[1.1] Loading CICIDS2017 dataset...")
        loader = CICIDS2017Loader(dataset_dir=dataset_dir)
        X_train, y_train = loader.load_and_prepare()
        
        logger.info(f"X_train shape: {X_train.shape}")
        logger.info(f"y_train shape: {y_train.shape}")
        logger.info(f"Classes: {np.bincount(y_train)}")
        
        # Train baseline model
        logger.info("\n[1.2] Training baseline RandomForest...")
        self.baseline_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            warm_start=True,  # Enable warm_start for fine-tuning
            n_jobs=-1,
            random_state=42,
            verbose=1
        )
        
        logger.info(f"Starting training at {datetime.now()}")
        self.baseline_model.fit(X_train, y_train)
        logger.info(f"Training complete at {datetime.now()}")
        
        # Evaluate on training data (baseline)
        logger.info("\n[1.3] Evaluating baseline model...")
        y_pred = self.baseline_model.predict(X_train)
        
        # Handle case where only one class exists
        proba = self.baseline_model.predict_proba(X_train)
        if proba.shape[1] == 1:
            # Only one class - use class 0 probability as 1.0
            y_pred_proba = np.ones(len(y_train))
        else:
            # Normal case - two classes
            y_pred_proba = proba[:, 1]
        
        self.baseline_metrics = {
            'accuracy': accuracy_score(y_train, y_pred),
            'precision': precision_score(y_train, y_pred, zero_division=0),
            'recall': recall_score(y_train, y_pred, zero_division=0),
            'f1': f1_score(y_train, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_train, y_pred_proba) if len(np.unique(y_train)) > 1 else 0.5,
        }
        
        logger.info("\nBaseline Metrics:")
        for metric, value in self.baseline_metrics.items():
            logger.info(f"  {metric}: {value:.4f}")
        
        # Save baseline model
        baseline_path = self.output_dir / "random_forest_baseline.joblib"
        joblib.dump(self.baseline_model, baseline_path)
        logger.info(f"\nBaseline model saved to: {baseline_path}")
        
        return X_train, y_train
    
    def phase_2_parse_real_logs(self, log_dir: str = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Phase 2: Parse 160k real Snort logs and extract features
        
        Returns: (X_real, y_real) for fine-tuning
        """
        self.log_section("PHASE 2: FEATURE EXTRACTION (160K REAL LOGS)")
        
        # Parse Snort logs
        logger.info("[2.1] Parsing Snort log files...")
        parser = SnortLogParser(log_dir=log_dir)
        logs, total_lines, failed = parser.parse_logs()
        
        dist = parser.get_label_distribution()
        logger.info("\nLabel distribution:")
        for key, val in dist.items():
            if isinstance(val, float):
                logger.info(f"  {key}: {val:.2f}%")
            else:
                logger.info(f"  {key}: {val}")
        
        if not logs:
            raise ValueError("No logs parsed successfully!")
        
        # Extract features using enhanced feature engineer
        logger.info("\n[2.2] Extracting enhanced features...")
        engineer = EnhancedFeatureEngineer()
        
        X_real = []
        y_real = []
        
        for idx, log in enumerate(logs):
            try:
                # Extract 12 base features (same format as CICIDS2017)
                feature_vector = [
                    float(log['dest_port']),
                    float(log['src_port']),
                    self._protocol_to_numeric(log['protocol']),
                    float(log['label']),  # threat_level
                    self._hash_sid(log['sid']),  # sid_normalized
                    0.0,  # fin_flag (not in Snort FAST format)
                    0.0,  # rst_flag
                    0.0,  # psh_flag
                    0.0,  # ack_flag
                    0.0,  # urg_flag
                    1.0 if self._is_private_ip(log['src_ip']) else 0.0,
                    1.0 if self._is_private_ip(log['dest_ip']) else 0.0,
                ]
                
                # Note: In production, also extract enhanced features:
                # enhanced = engineer.extract_all_features(log)
                # This requires properly tracking state across logs
                
                X_real.append(feature_vector)
                y_real.append(log['label'])
                
                if (idx + 1) % 50000 == 0:
                    logger.info(f"  Extracted {idx + 1} feature vectors")
            
            except Exception as e:
                logger.debug(f"Error extracting features for log {idx}: {e}")
                continue
        
        X_real = np.array(X_real, dtype=np.float32)
        y_real = np.array(y_real, dtype=np.int32)
        
        logger.info(f"\nReal log features: {X_real.shape}")
        logger.info(f"Real log labels: {y_real.shape}")
        logger.info(f"Classes: {np.bincount(y_real)}")
        
        return X_real, y_real
    
    def phase_3_fine_tune(self, X_real: np.ndarray, y_real: np.ndarray, dataset_dir: str = None):
        """
        Phase 3: Fine-tune baseline model with warm_start using real logs
        
        warm_start=True allows us to continue training the existing model
        with new data (transfer learning)
        """
        self.log_section("PHASE 3: FINE-TUNING (TRANSFER LEARNING)")
        
        if self.baseline_model is None:
            raise ValueError("Baseline model not trained yet!")
        
        logger.info("[3.1] Preparing fine-tuning data...")
        logger.info(f"Real log data shape: {X_real.shape}, classes: {np.unique(y_real)}")
        
        # Reload CICIDS benign data to mix with real logs
        # This ensures we have both classes during fine-tuning
        logger.info("Loading benign samples from CICIDS2017 for balanced fine-tuning...")
        from cicids_loader import CICIDS2017Loader
        cicids = CICIDS2017Loader(dataset_dir)
        X_cicids, y_cicids = cicids.load_and_prepare()
        
        # Filter only benign samples from CICIDS (class 0)
        benign_mask = y_cicids == 0
        X_benign = X_cicids[benign_mask]
        y_benign = y_cicids[benign_mask]
        
        # Take a sample of benign data proportional to real logs
        # Typically: 1 benign per threat for 50-50 split
        sample_size = min(X_benign.shape[0], X_real.shape[0])
        sample_indices = np.random.choice(X_benign.shape[0], sample_size, replace=False)
        X_benign_sample = X_benign[sample_indices]
        y_benign_sample = y_benign[sample_indices]
        
        logger.info(f"  Benign samples: {X_benign_sample.shape[0]}")
        logger.info(f"  Threat samples: {X_real.shape[0]}")
        
        # Combine benign and threat data for fine-tuning
        X_finetune = np.vstack([X_benign_sample, X_real])
        y_finetune = np.concatenate([y_benign_sample, y_real])
        
        logger.info(f"  Combined fine-tune data: {X_finetune.shape}")
        logger.info(f"  Class distribution: {np.unique(y_finetune, return_counts=True)[1]}")
        
        # Continue training with warm_start
        logger.info(f"\n[3.2] Starting fine-tuning at {datetime.now()}")
        self.baseline_model.fit(X_finetune, y_finetune)
        logger.info(f"Fine-tuning complete at {datetime.now()}")
        
        # Evaluate fine-tuned model
        logger.info("\n[3.3] Evaluating fine-tuned model...")
        
        # Test on real log data only
        y_pred = self.baseline_model.predict(X_real)
        y_pred_proba = self.baseline_model.predict_proba(X_real)[:, 1]
        
        self.finetuned_metrics = {
            'accuracy': accuracy_score(y_real, y_pred),
            'precision': precision_score(y_real, y_pred, zero_division=0),
            'recall': recall_score(y_real, y_pred, zero_division=0),
            'f1': f1_score(y_real, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_real, y_pred_proba),
        }
        
        logger.info("\nFine-tuned Metrics (evaluated on real logs):")
        for metric, value in self.finetuned_metrics.items():
            logger.info(f"  {metric}: {value:.4f}")
        
        # Save fine-tuned model
        finetuned_path = self.output_dir / "random_forest_finetuned.joblib"
        joblib.dump(self.baseline_model, finetuned_path)
        logger.info(f"\nFine-tuned model saved to: {finetuned_path}")
    
    def compare_models(self):
        """Compare baseline vs fine-tuned model metrics."""
        self.log_section("MODEL COMPARISON: BASELINE VS FINE-TUNED")
        
        comparison_data = []
        
        for metric in self.baseline_metrics.keys():
            baseline_val = self.baseline_metrics.get(metric, 0)
            finetuned_val = self.finetuned_metrics.get(metric, 0)
            improvement = ((finetuned_val - baseline_val) / baseline_val * 100) if baseline_val != 0 else 0
            
            comparison_data.append({
                'Metric': metric.upper(),
                'Baseline': f"{baseline_val:.4f}",
                'Fine-tuned': f"{finetuned_val:.4f}",
                'Improvement': f"{improvement:+.2f}%"
            })
            
            logger.info(f"{metric.upper():12} | Baseline: {baseline_val:.4f} | Fine-tuned: {finetuned_val:.4f} | Change: {improvement:+.2f}%")
        
        # Save comparison to CSV
        comparison_df = pd.DataFrame(comparison_data)
        comparison_path = self.output_dir / "model_comparison.csv"
        comparison_df.to_csv(comparison_path, index=False)
        logger.info(f"\nComparison saved to: {comparison_path}")
    
    def run_complete_pipeline(self, dataset_dir: str = None, log_dir: str = None):
        """Run all 3 phases."""
        try:
            self.log_section("ML MODEL RETRAINING PIPELINE")
            logger.info(f"Start time: {datetime.now()}")
            logger.info(f"Output directory: {self.output_dir}\n")
            
            # Phase 1: Train baseline
            X_train, y_train = self.phase_1_train_baseline(dataset_dir=dataset_dir)
            
            # Phase 2: Parse real logs
            X_real, y_real = self.phase_2_parse_real_logs(log_dir=log_dir)
            
            # Phase 3: Fine-tune
            self.phase_3_fine_tune(X_real, y_real, dataset_dir=dataset_dir)
            
            # Compare models
            self.compare_models()
            
            self.log_section("PIPELINE COMPLETE")
            logger.info(f"End time: {datetime.now()}")
            logger.info(f"Models saved to: {self.output_dir}")
        
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            raise
    
    def _protocol_to_numeric(self, protocol: str) -> float:
        """Map protocol to numeric value."""
        mapping = {'TCP': 1.0, 'UDP': 2.0, 'ICMP': 3.0}
        return mapping.get(protocol.upper(), 4.0)
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private."""
        try:
            parts = list(map(int, ip_str.split('.')))
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            return False
        except:
            return False
    
    def _hash_sid(self, sid: str) -> float:
        """Convert SID to normalized feature."""
        try:
            sid_int = int(sid)
            return float(sid_int % 1000) / 1000.0
        except:
            return 0.5


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("training_pipeline.log"),
            logging.StreamHandler()
        ]
    )
    
    # Use absolute paths from project root
    project_root = Path(__file__).parent.parent.parent
    dataset_path = str(project_root / "dataset")
    logs_path = str(project_root / "real_logs")
    models_path = str(project_root / "Backend" / "ml_training" / "trained_models")
    
    logger.info(f"Resolved paths:")
    logger.info(f"  Dataset: {dataset_path}")
    logger.info(f"  Real logs: {logs_path}")
    logger.info(f"  Models output: {models_path}")
    
    # Run pipeline
    pipeline = MLTrainingPipeline(output_dir=models_path)
    pipeline.run_complete_pipeline(dataset_dir=dataset_path, log_dir=logs_path)
