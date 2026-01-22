"""
ML Features Module - Feature extraction and threat classification

Components:
- SimplifiedFeatureExtractor: Convert Snort alerts to 12 essential features
- ModelLoader: Load and manage trained ML models
- ThreatAnalyzer: End-to-end threat analysis pipeline
"""

from .feature_extractor_simple import SimplifiedFeatureExtractor
from .model_loader import ModelLoader
from .threat_analyzer import ThreatAnalyzer

__all__ = ['SimplifiedFeatureExtractor', 'ModelLoader', 'ThreatAnalyzer']

