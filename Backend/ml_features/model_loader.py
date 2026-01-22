"""
Model Loader - Load and manage trained ML models
Loads models from trained_models/ directory for threat classification
"""

import os
import logging
import pickle
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)


class ModelLoader:
    """
    Load and manage trained ML models.
    
    Supports:
    - Pickle models (.pkl)
    - Joblib models (.joblib)
    - Scikit-learn models
    - Custom models
    """
    
    def __init__(self, models_dir='trained_models'):
        """
        Initialize model loader.
        
        Args:
            models_dir: Directory containing trained models
        """
        self.models_dir = Path(models_dir)
        self.models = {}
        self.model_metadata = {}
    
    def load_model(self, model_name, model_path=None):
        """
        Load a single model.
        
        Args:
            model_name: Name/identifier for the model
            model_path: Path to model file (optional, auto-detects if None)
        
        Returns:
            Loaded model object or None if failed
        """
        try:
            if model_path is None:
                # Auto-detect model file
                model_path = self._find_model_file(model_name)
            
            if not model_path or not os.path.exists(model_path):
                logger.warning(f"Model file not found: {model_path}")
                return None
            
            # Determine file type and load accordingly
            if model_path.endswith('.pkl'):
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
            elif model_path.endswith('.joblib'):
                model = joblib.load(model_path)
            else:
                logger.error(f"Unsupported model format: {model_path}")
                return None
            
            self.models[model_name] = model
            logger.info(f"Loaded model: {model_name} from {model_path}")
            
            return model
            
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {str(e)}")
            return None
    
    def load_all_models(self):
        """
        Auto-discover and load all models from models_dir.
        
        Returns:
            dict: Loaded models with names as keys
        """
        if not self.models_dir.exists():
            logger.warning(f"Models directory not found: {self.models_dir}")
            return {}
        
        model_files = list(self.models_dir.glob('*.pkl')) + list(self.models_dir.glob('*.joblib'))
        
        for model_file in model_files:
            model_name = model_file.stem  # filename without extension
            self.load_model(model_name, str(model_file))
        
        logger.info(f"Loaded {len(self.models)} models")
        return self.models
    
    def get_model(self, model_name):
        """
        Get a loaded model by name.
        
        Args:
            model_name: Name of the model
        
        Returns:
            Model object or None if not loaded
        """
        return self.models.get(model_name)
    
    def predict(self, model_name, features):
        """
        Make predictions using a loaded model.
        
        Args:
            model_name: Name of the model to use
            features: Feature vector (numpy array)
        
        Returns:
            dict: Prediction results with:
                  - prediction: predicted class/value
                  - probability: confidence score (if available)
                  - error: error message if failed
        """
        try:
            model = self.get_model(model_name)
            if model is None:
                return {
                    'prediction': None,
                    'probability': None,
                    'error': f'Model {model_name} not loaded',
                }
            
            # Ensure features is 2D for sklearn compatibility
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Make prediction
            prediction = model.predict(features)[0]
            
            # Try to get probability
            probability = None
            if hasattr(model, 'predict_proba'):
                probs = model.predict_proba(features)[0]
                probability = float(max(probs))
            
            return {
                'prediction': prediction,
                'probability': probability,
                'error': None,
            }
            
        except Exception as e:
            logger.error(f"Prediction failed with {model_name}: {str(e)}")
            return {
                'prediction': None,
                'probability': None,
                'error': str(e),
            }
    
    def list_loaded_models(self):
        """Get list of loaded model names"""
        return list(self.models.keys())
    
    def _find_model_file(self, model_name):
        """Auto-find model file by name"""
        if not self.models_dir.exists():
            return None
        
        # Check for exact matches
        pkl_file = self.models_dir / f'{model_name}.pkl'
        if pkl_file.exists():
            return str(pkl_file)
        
        joblib_file = self.models_dir / f'{model_name}.joblib'
        if joblib_file.exists():
            return str(joblib_file)
        
        return None
