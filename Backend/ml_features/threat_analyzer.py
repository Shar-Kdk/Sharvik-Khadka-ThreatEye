"""
ThreatEye ML Integration - Use Trained Random Forest Model with Snort Alerts
US015 Implementation - Feature extraction + ML prediction

This module integrates the trained Random Forest model (simplified with 12 features)
with ThreatEye's Snort alert ingestion pipeline.

Updated: Uses SimplifiedFeatureExtractor (12 features) instead of 55 CIC-IDS17 features
- 12x faster training (~5 minutes vs 2 hours)
- Better feature alignment with Snort alert data
- Simpler, more maintainable pipeline
"""

import numpy as np
import logging
from ml_features.feature_extractor_simple import SimplifiedFeatureExtractor
from ml_features.model_loader import ModelLoader

logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """
    End-to-end threat analysis using trained Random Forest model.
    
    Pipeline:
    1. Extract 12 simplified features from Snort alert
    2. Load trained Random Forest model  
    3. Make binary prediction: Benign (0) vs Attack (1)
    4. Return threat classification with confidence score
    
    Features:
    - dest_port, src_port (normalized)
    - protocol (TCP/UDP/ICMP encoded)
    - threat_level (safe/medium/high encoded)
    - sid (normalized)
    - TCP flags (FIN, RST, PSH, ACK, URG)
    - IP location (src/dest internal or external)
    """
    
    def __init__(self, model_name='random_forest_simplified', models_dir='trained_models'):
        """
        Initialize threat analyzer with simplified feature extractor.
        
        Args:
            model_name: Name of trained model (without .joblib extension)
            models_dir: Directory containing trained models
        """
        self.feature_extractor = SimplifiedFeatureExtractor()
        self.model_loader = ModelLoader(models_dir)
        self.model = None
        self.model_loaded = False
        
        # Try to load the model
        self._load_model(model_name)
    
    def _load_model(self, model_name):
        """Load the trained Random Forest model."""
        try:
            self.model = self.model_loader.load_model(model_name)
            if self.model:
                self.model_loaded = True
                logger.info(f"✅ Loaded Random Forest model: {model_name}")
            else:
                logger.warning(f"⚠️  Could not load model: {model_name}")
        except Exception as e:
            logger.error(f"❌ Error loading model: {str(e)}")
    
    def analyze_alert(self, alert):
        """
        Analyze a single Snort alert using Random Forest model.
        
        Args:
            alert: Alert object from database OR dict with alert data
                   Expected fields: dest_port, src_port, protocol, threat_level,
                                   sid, message, src_ip, dest_ip
        
        Returns:
            dict with keys:
                - alert_id: Alert ID (if available)
                - threat_class: 0 (Benign) or 1 (Attack)
                - confidence: Prediction confidence (0-1)
                - features_extracted: Number of features extracted (always 12)
                - error: Error message if any
        
        Example:
            >>> alert = Alert.objects.first()
            >>> analyzer = ThreatAnalyzer()
            >>> result = analyzer.analyze_alert(alert)
            >>> if result['threat_class'] == 1:
            ...     print(f"🚨 Attack detected! Confidence: {result['confidence']:.2%}")
        """
        try:
            if not self.model_loaded:
                alert_id = getattr(alert, 'id', None) or alert.get('id') if isinstance(alert, dict) else None
                return {
                    'alert_id': alert_id,
                    'threat_class': None,
                    'confidence': None,
                    'features_extracted': 0,
                    'error': 'Model not loaded',
                }
            
            # Convert alert object to dict if needed
            alert_dict = self._alert_to_dict(alert)
            alert_id = alert.get('id') if isinstance(alert, dict) else alert.id
            
            # Extract features
            try:
                features = self.feature_extractor.extract_features(alert_dict)
            except Exception as e:
                return {
                    'alert_id': alert_id,
                    'threat_class': None,
                    'confidence': None,
                    'features_extracted': 0,
                    'error': f'Feature extraction failed: {str(e)}',
                }
            
            # Make prediction
            prediction = self.model.predict([features])[0]
            confidence = max(self.model.predict_proba([features])[0])
            
            return {
                'alert_id': alert_id,
                'threat_class': int(prediction),
                'confidence': float(confidence),
                'features_extracted': 12,
                'error': None,
            }
            
        except Exception as e:
            alert_id = getattr(alert, 'id', None) or (alert.get('id') if isinstance(alert, dict) else None)
            logger.error(f"Alert analysis failed: {str(e)}")
            return {
                'alert_id': alert_id,
                'threat_class': None,
                'confidence': None,
                'features_extracted': 0,
                'error': str(e),
            }

    def _alert_to_dict(self, alert):
        """Convert Django Alert model to dictionary for feature extraction."""
        if isinstance(alert, dict):
            return alert
        
        return {
            'dest_port': alert.dest_port,
            'src_port': alert.src_port,
            'protocol': alert.protocol,
            'threat_level': alert.threat_level,
            'sid': alert.sid,
            'message': alert.message,
            'src_ip': str(alert.src_ip),
            'dest_ip': str(alert.dest_ip),
        }
    
    def analyze_batch(self, alerts, batch_size=1000):
        """
        Analyze multiple alerts efficiently.
        
        Args:
            alerts: List or QuerySet of alerts to analyze
            batch_size: Process in batches for memory efficiency
        
        Returns:
            dict with summary statistics and per-alert results
        """
        if not self.model_loaded:
            return {
                'total': len(alerts),
                'analyzed': 0,
                'benign': 0,
                'attack': 0,
                'error': 'Model not loaded',
            }
        
        results = []
        attack_count = 0
        benign_count = 0
        error_count = 0
        
        # Convert to list if QuerySet
        alerts_list = list(alerts)
        total = len(alerts_list)
        
        for i in range(0, total, batch_size):
            batch = alerts_list[i:i+batch_size]
            
            for alert in batch:
                result = self.analyze_alert(alert)
                results.append(result)
                
                if result['error'] is None:
                    if result['threat_class'] == 1:
                        attack_count += 1
                    else:
                        benign_count += 1
                else:
                    error_count += 1
        
        return {
            'total': total,
            'analyzed': total - error_count,
            'benign': benign_count,
            'attack': attack_count,
            'errors': error_count,
            'attack_percentage': (attack_count / (total - error_count) * 100) if total > error_count else 0,
            'results': results,
        }
    
    def get_threat_label(self, threat_class):
        """Get human-readable threat label."""
        if threat_class == 0:
            return "✅ BENIGN"
        elif threat_class == 1:
            return "🚨 ATTACK"
        else:
            return "❓ UNKNOWN"
    
    def get_stats(self):
        """Get analyzer statistics."""
        stats = {
            'model_loaded': self.model_loaded,
            'feature_extractor': self.feature_extractor.get_stats(),
        }
        return stats


# Usage example - Run from Django shell
def example_usage():
    """
    Example: Use the threat analyzer with Snort alerts
    
    Run in Django shell:
    python manage.py shell
    >>> from ml_features.threat_analyzer import ThreatAnalyzer
    >>> analyzer = ThreatAnalyzer()
    >>> # Analyze single alert
    >>> from alerts.models import Alert
    >>> alert = Alert.objects.first()
    >>> result = analyzer.analyze_alert(alert)
    >>> print(f"Alert {result['alert_id']}: {analyzer.get_threat_label(result['threat_class'])}")
    >>> print(f"Confidence: {result['confidence']:.2%}")
    >>> 
    >>> # Analyze all alerts
    >>> alerts = Alert.objects.all()[:100]
    >>> batch_results = analyzer.analyze_batch(alerts)
    >>> print(f"Summary: {batch_results['attack']} attacks detected out of {batch_results['analyzed']}")
    """
    pass
