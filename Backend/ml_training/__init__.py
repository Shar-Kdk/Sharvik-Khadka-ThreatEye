"""
ML Training Module - Model Retraining Pipeline

This module implements a 3-phase transfer learning approach to retrain the
ThreatEye ML model from scratch using the user's real network data.

Modules:
- snort_log_parser.py: Parses 160k real Snort FAST format logs
- cicids_loader.py: Loads CICIDS2017 dataset for baseline training
- enhanced_features.py: Extracts 7 network-specific feature categories
- train_model.py: Complete 3-phase training pipeline (baseline → fine-tuning)
"""

__version__ = "1.0.0"
