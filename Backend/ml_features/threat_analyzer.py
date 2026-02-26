"""
ThreatEye ML Integration - use trained Random Forest model with Snort alerts
"""

import numpy as np
import logging
from ml_features.feature_extractor_simple import SimplifiedFeatureExtractor
from ml_features.model_loader import ModelLoader

logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """End-to-end threat analysis using Random Forest model with 12 simplified features."""
    
    def __init__(self, model_name='random_forest_local', models_dir='trained_models'):
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
        
        # Load the model during initialization
        self._load_model(model_name)
    
    def _load_model(self, model_name):
        """Load the Random Forest model."""
        try:
            self.model = self.model_loader.load_model(model_name)
            if self.model:
                self.model_loaded = True
                logger.info(f"Loaded model: {model_name}")
            else:
                logger.warning(f"Could not load model: {model_name}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
    
    def analyze_alert(self, alert):
        """Analyze a single alert using Random Forest model."""
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
            
            # Make prediction (verbose=0 suppresses joblib parallel output)
            # Set model verbosity to 0 if available
            original_verbose = getattr(self.model, 'verbose', 0)
            if hasattr(self.model, 'verbose'):
                self.model.verbose = 0
            
            try:
                prediction = self.model.predict([features])[0]

                # Treat confidence as probability of the ATTACK class (class label 1) when available
                proba = self.model.predict_proba([features])[0]
                try:
                    classes = list(getattr(self.model, 'classes_', []))
                    confidence = float(proba[classes.index(1)]) if 1 in classes else float(max(proba))
                except Exception:
                    confidence = float(max(proba))
            finally:
                if hasattr(self.model, 'verbose'):
                    self.model.verbose = original_verbose
            
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
        
        try:
            return {
                'dest_port': getattr(alert, 'dest_port', None),
                'src_port': getattr(alert, 'src_port', None),
                'protocol': str(getattr(alert, 'protocol', 'TCP')).strip() or 'TCP',
                'threat_level': str(getattr(alert, 'threat_level', 'safe')).strip().lower() or 'safe',
                'sid': str(getattr(alert, 'sid', 'unknown')).strip() or 'unknown',
                'message': str(getattr(alert, 'message', 'Unknown alert')).strip() or 'Unknown alert',
                'src_ip': str(getattr(alert, 'src_ip', '0.0.0.0')),
                'dest_ip': str(getattr(alert, 'dest_ip', '0.0.0.0')),
            }
        except Exception as e:
            logger.error(f"Error converting alert to dict: {e}, returning safe defaults")
            return {
                'dest_port': None,
                'src_port': None,
                'protocol': 'TCP',
                'threat_level': 'safe',
                'sid': 'unknown',
                'message': 'Unknown alert',
                'src_ip': '0.0.0.0',
                'dest_ip': '0.0.0.0',
            }
    
    def analyze_batch(self, alerts, batch_size=1000):
        """Analyze multiple alerts efficiently and return summary statistics."""
        try:
            alerts_list = list(alerts) if alerts else []
            total = len(alerts_list)
            
            if total == 0:
                return {
                    'total': 0,
                    'analyzed': 0,
                    'benign': 0,
                    'attack': 0,
                    'errors': 0,
                    'error': None,
                    'attack_percentage': 0,
                    'results': [],
                }
            
            if not self.model_loaded:
                return {
                    'total': total,
                    'analyzed': 0,
                    'benign': 0,
                    'attack': 0,
                    'errors': total,
                    'error': 'Model not loaded',
                    'attack_percentage': 0,
                    'results': [],
                }
            
            results = []
            attack_count = 0
            benign_count = 0
            error_count = 0
            
            for i in range(0, total, batch_size):
                batch = alerts_list[i:i+batch_size]
                
                for alert in batch:
                    try:
                        result = self.analyze_alert(alert)
                        results.append(result)
                        
                        if result['error'] is None:
                            if result['threat_class'] == 1:
                                attack_count += 1
                            else:
                                benign_count += 1
                        else:
                            error_count += 1
                    except Exception as e:
                        logger.warning(f"Error analyzing alert in batch: {e}")
                        error_count += 1
                        results.append({
                            'alert_id': None,
                            'threat_class': None,
                            'confidence': None,
                            'features_extracted': 0,
                            'error': f'Batch analysis error: {str(e)}',
                        })
            
            analyzed = total - error_count
            attack_percentage = (attack_count / analyzed * 100) if analyzed > 0 else 0
            
            return {
                'total': total,
                'analyzed': analyzed,
                'benign': benign_count,
                'attack': attack_count,
                'errors': error_count,
                'error': None,
                'attack_percentage': attack_percentage,
                'results': results,
            }
        
        except Exception as e:
            logger.error(f"Unexpected error in analyze_batch: {e}")
            return {
                'total': 0,
                'analyzed': 0,
                'benign': 0,
                'attack': 0,
                'errors': 1,
                'error': f'Unexpected error: {str(e)}',
                'attack_percentage': 0,
                'results': [],
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
