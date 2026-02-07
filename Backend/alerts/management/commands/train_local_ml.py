import random
import re
from pathlib import Path

import joblib
import numpy as np
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from alerts.models import Alert
from ml_features.feature_extractor_simple import SimplifiedFeatureExtractor


class Command(BaseCommand):
    help = (
        'Train a RandomForest model from locally ingested Snort alerts in the DB.\n'
        'Labels: safe=benign (0), medium/high=attack (1).\n'
        'Saves to Backend/trained_models/<model-name>.joblib'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--model-name',
            type=str,
            default='random_forest_local',
            help='Output model name (no extension). Default: random_forest_local',
        )
        parser.add_argument(
            '--test-size',
            type=float,
            default=0.2,
            help='Hold-out test fraction (0-0.5). Default: 0.2',
        )
        parser.add_argument(
            '--random-state',
            type=int,
            default=42,
            help='Random seed for sampling/splitting. Default: 42',
        )
        parser.add_argument(
            '--n-estimators',
            type=int,
            default=200,
            help='Number of trees. Default: 200',
        )
        parser.add_argument(
            '--max-depth',
            type=int,
            default=20,
            help='Max tree depth. Default: 20',
        )
        parser.add_argument(
            '--max-benign',
            type=int,
            default=0,
            help='Limit benign samples (0=all). Useful for faster experiments.',
        )
        parser.add_argument(
            '--max-attack',
            type=int,
            default=0,
            help='Limit attack samples (0=all). Useful for faster experiments.',
        )
        parser.add_argument(
            '--min-attack',
            type=int,
            default=20,
            help='Warn if attack samples are below this count. Default: 20',
        )
        parser.add_argument(
            '--no-save',
            action='store_true',
            help='Train and evaluate but do not write model file.',
        )

    def handle(self, *args, **options):
        model_name = (options['model_name'] or '').strip()
        if not model_name:
            raise CommandError('--model-name cannot be empty')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', model_name):
            raise CommandError('Invalid --model-name. Use only letters, digits, underscore, hyphen (max 64).')

        test_size = float(options['test_size'])
        if test_size < 0 or test_size > 0.5:
            raise CommandError('--test-size must be between 0 and 0.5')

        random_state = int(options['random_state'])
        n_estimators = int(options['n_estimators'])
        max_depth = int(options['max_depth'])
        max_benign = int(options['max_benign'])
        max_attack = int(options['max_attack'])
        min_attack = int(options['min_attack'])

        if n_estimators <= 0:
            raise CommandError('--n-estimators must be > 0')
        if max_depth <= 0:
            raise CommandError('--max-depth must be > 0')
        if max_benign < 0 or max_attack < 0:
            raise CommandError('--max-benign/--max-attack must be >= 0')

        benign_qs = Alert.objects.filter(threat_level=Alert.THREAT_SAFE)
        attack_qs = Alert.objects.filter(threat_level__in=[Alert.THREAT_MEDIUM, Alert.THREAT_HIGH])

        benign_count = benign_qs.count()
        attack_count = attack_qs.count()

        self.stdout.write(self.style.SUCCESS('Local training dataset summary:'))
        self.stdout.write(f'  Benign (safe):  {benign_count}')
        self.stdout.write(f'  Attack (m/h):   {attack_count}')

        if benign_count == 0 or attack_count == 0:
            raise CommandError('Need at least 1 benign and 1 attack alert in DB to train.')

        if attack_count < min_attack:
            self.stdout.write(
                self.style.WARNING(
                    f'WARNING: Only {attack_count} attack samples found. '
                    'Model quality will be unstable; generate more attack alerts if possible.'
                )
            )

        # Optional sampling (use deterministic shuffle)
        rng = random.Random(random_state)

        if max_benign and benign_count > max_benign:
            benign_ids = list(benign_qs.values_list('id', flat=True))
            rng.shuffle(benign_ids)
            benign_qs = Alert.objects.filter(id__in=benign_ids[:max_benign])
            self.stdout.write(f'  Using benign sample: {benign_qs.count()}')

        if max_attack and attack_count > max_attack:
            attack_ids = list(attack_qs.values_list('id', flat=True))
            rng.shuffle(attack_ids)
            attack_qs = Alert.objects.filter(id__in=attack_ids[:max_attack])
            self.stdout.write(f'  Using attack sample:  {attack_qs.count()}')

        extractor = SimplifiedFeatureExtractor()

        feature_fields = [
            'dest_port',
            'src_port',
            'protocol',
            'threat_level',
            'sid',
            'message',
            'src_ip',
            'dest_ip',
        ]

        X_list = []
        y_list = []

        for row in benign_qs.values(*feature_fields):
            X_list.append(extractor.extract_features(row))
            y_list.append(0)

        for row in attack_qs.values(*feature_fields):
            X_list.append(extractor.extract_features(row))
            y_list.append(1)

        X = np.vstack(X_list).astype(np.float32, copy=False)
        y = np.array(y_list, dtype=np.int64)

        # Train/test split
        if test_size > 0 and len(y) >= 10 and len(set(y.tolist())) == 2:
            from sklearn.model_selection import train_test_split

            X_train, X_test, y_train, y_test = train_test_split(
                X,
                y,
                test_size=test_size,
                random_state=random_state,
                stratify=y,
            )
        else:
            X_train, y_train = X, y
            X_test, y_test = None, None

        from sklearn.ensemble import RandomForestClassifier

        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
            class_weight='balanced',
        )

        self.stdout.write('\nTraining model...')
        model.fit(X_train, y_train)

        # Evaluation
        self.stdout.write(self.style.SUCCESS('Training complete.'))

        if X_test is not None:
            from sklearn.metrics import classification_report, confusion_matrix

            y_pred = model.predict(X_test)
            cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
            self.stdout.write('\nConfusion matrix (rows=true, cols=pred) [benign, attack]:')
            self.stdout.write(str(cm))
            self.stdout.write('\nClassification report:')
            self.stdout.write(classification_report(y_test, y_pred, target_names=['benign', 'attack']))
        else:
            train_acc = float(model.score(X_train, y_train))
            self.stdout.write(f'No test split; training accuracy: {train_acc:.4f}')

        if options['no_save']:
            self.stdout.write(self.style.WARNING('\n--no-save specified; skipping file write.'))
            return

        models_dir = Path(settings.BASE_DIR) / 'trained_models'
        models_dir.mkdir(parents=True, exist_ok=True)

        model_path = models_dir / f'{model_name}.joblib'
        joblib.dump(model, model_path)

        # Save feature names used by this model (for debugging/inspection)
        feature_names_path = models_dir / f'{model_name}_feature_names.joblib'
        joblib.dump(SimplifiedFeatureExtractor.get_feature_names(), feature_names_path)

        self.stdout.write(
            self.style.SUCCESS(
                f'\n✓ Saved model to {model_path.relative_to(settings.BASE_DIR)}'
            )
        )
        self.stdout.write(
            f'  Feature names: {feature_names_path.relative_to(settings.BASE_DIR)}'
        )
        self.stdout.write(
            self.style.WARNING(
                "To use this model at runtime, set environment variable THREATEYE_ML_MODEL_NAME="
                f"{model_name} (or let ThreatEye auto-detect it if enabled)."
            )
        )
