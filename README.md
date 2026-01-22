# ThreatEye - Auth & Subscription Platform

**Secure User Authentication & Organization-level Subscription Management**

ThreatEye is a streamlined web platform designed for multi-tenant organization management. It provides a robust foundation for user authentication (with email verification) and automated subscription lifecycle management integrated with Stripe.

---

## 🎯 Project Scope

The project focuses on three core pillars:
1. **Identity & Access**: Secure authentication flow with mandatory email verification and role-based access control (Platform Owners vs. Organization Admins).
2. **Subscription Management**: Complete Stripe integration for plan selection, payment processing, and automatic organization activation.
3. **Live Traffic Monitoring**: Near real-time Snort log ingestion for alert and packet visibility.

### ✅ Core Features
- **JWT Authentication**: Secure token-based sessions with 1-hour validity.
- **Email Verification**: Mandatory 6-digit verification codes sent via SMTP (Gmail).
- **Stripe Integration**: Real-time payment processing for Professional and Basic plans.
- **Auto-Activation**: Organizations are automatically marked as `Active` and their `subscription_tier` is updated instantly upon successful Stripe payment.
- **Multi-Tenancy**: Support for multiple organizations with distinct user capacity limits (Max Users).
- **Admin Dashboard**: Specialized views for Platform Owners to manage all organizations and subscriptions.
- **Plan Management**: Organization Admins can view current plans, renewal dates, and full billing history.
- **Live Network Traffic Monitoring**: Real-time Snort ingestion and visualization with 5-second refresh.
- **Alert + Packet Ingestion**: Reads `snort.alert.fast*` and `snort.log*` from the `snort_logs` folder.
- **Threat Level Alerts (Priority-Based)**:
   - **Priority 1 -> High (Red)**
   - **Priority 2 -> Medium (Yellow)**
   - **Priority 3 -> Safe (Green)**
- **Live Table Pagination**: Dashboard traffic table supports pagination with a maximum of 50 rows per page.

---

## 🛠 Tech Stack

### Backend
- **Framework:** Django 4.2.16
- **API:** Django REST Framework 3.15.2
- **Authentication:** Simple JWT 5.4.0 (JWT)
- **Payment Gateway:** Stripe SDK 8.1.0
- **Database:** MySQL / MariaDB (via PyMySQL)
- **Email:** SMTP (Gmail) for verification codes
- **ML/Threat Detection:** scikit-learn RandomForest, pandas, numpy, joblib

### Frontend
- **Framework:** React 19 / Vite
- **Styling:** Tailwind CSS (Dark Theme / Glassmorphism)
- **Routing:** React Router 7
- **Icons**: Custom SVG assets

---

## 📁 Project Structure

```
ThreatEye/
├── Backend/
│   ├── authentication/      # User models, Roles, and Email Verification
│   ├── subscription/        # Stripe integration, Plans, and Payment logic
│   ├── alerts/              # Snort log parsing, ingestion, and live traffic API
│   ├── ml_features/         # ML threat detection & feature extraction
│   │   ├── feature_extractor_simple.py  # 12-feature extractor
│   │   ├── threat_analyzer.py          # Alert classification pipeline
│   │   └── model_loader.py             # ML model utilities
│   ├── trained_models/      # Trained RandomForest models (production)
│   │   ├── random_forest_simplified.joblib     # Threat detection model
│   │   └── simple_feature_names.joblib         # Feature metadata
│   ├── ThreatEye/           # Project settings & URL routing
│   └── manage.py            # Django CLI
└── Frontend/
    ├── src/
    │   ├── components/      # Login, Verification, and Sidebar components
    │   ├── pages/           # Dashboard, Overview, and Plan Management
    │   ├── services/        # API client (Axios/Fetch)
    │   └── App.jsx          # Route gates and Global state
```

---

## 🚀 Quick Start

### Backend Setup
1. **Navigate & Environment**
   ```bash
   cd Backend
   python -m venv .venv
   source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
   ```
2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Configure Environment**
   Create a `.env` file with:
   - `STRIPE_SECRET_KEY`
   - `EMAIL_HOST_USER` / `EMAIL_HOST_PASSWORD`
   - `DATABASE_URL`
4. **Initialize**
   ```bash
   python manage.py migrate
   python manage.py runserver
   ```

### Frontend Setup
1. **Navigate & Install**
   ```bash
   cd Frontend
   npm install
   ```
2. **Run Dev Server**
   ```bash
   npm run dev
   ```

---

## 📡 Key API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login/` | Auth with email/password → returns JWT |
| POST | `/api/auth/verify-email/` | Verify 6-digit code → logs in user |
| GET | `/api/auth/profile/` | Fetch current user & organization data |

### Subscriptions
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/subscriptions/plans/` | List available pricing tiers |
| POST | `/subscriptions/initiate/` | Initiate Stripe PaymentIntent |
| POST | `/subscriptions/verify/` | Confirm payment & activate organization |
| GET | `/subscriptions/status/` | Check active plan & renewal status |

### Alerts & Live Traffic
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts/live/?limit=100` | Fetch latest Snort alerts with threat levels (auto-ingests new logs) |

---

## 🤖 ML-Based Threat Detection

### Model Architecture
- **Algorithm:** Random Forest Classifier (150 trees, max_depth=20)
- **Training Dataset:** CIC-IDS2017 (2,830,743 samples across 8 files)
- **Features:** 12 simplified features directly extracted from Snort alerts
- **Performance Metrics:**
  - **Accuracy:** 94.84%
  - **Recall:** 98.91% (catches 98.91% of attacks)
  - **Precision:** 79.74%
  - **F1-Score:** 88.30%
- **Training Time:** 1.73 minutes (fully optimized)
- **Model Size:** 14.68 MB (joblib format)

### Feature Set (12 Total)
| Feature | Type | Source |
|---------|------|--------|
| Destination Port | Continuous | Snort alert (extracted) |
| Source Port | Continuous | Snort alert (extracted) |
| Protocol Type | Categorical | Snort alert (encoded) |
| TCP Flags (5 variants) | Binary | Snort packet data |
| Threat Level (Priority) | Categorical | Snort rule priority |
| SID (Signature ID) | Continuous | Snort rule ID |
| Source IP Internal | Binary | Hardcoded validation |
| Destination IP Internal | Binary | Hardcoded validation |

### Deployment Ready
- ✅ Model trained on production CIC-IDS2017 dataset
- ✅ Binary classification: Benign (0) vs. Attack (1)
- ✅ Sub-100ms prediction latency per alert
- ✅ Integrated with [ThreatAnalyzer](Backend/ml_features/threat_analyzer.py)
- ✅ Features work across different Snort rulesets (no retraining needed)

### Usage
```python
from ml_features import ThreatAnalyzer

analyzer = ThreatAnalyzer()
alert = {
    'src_port': 443,
    'dest_port': 12345,
    'protocol': 'TCP',
    'flags': 'SYN',
    'priority': 2,
    'sid': 123456,
    'src_ip': '10.0.0.1',
    'dest_ip': '192.168.1.1'
}

prediction = analyzer.analyze_alert(alert)
# Returns: {'label': 'Attack', 'confidence': 0.965, 'threat_level': 'High'}
```

---

## 🔒 Security & Optimization
- **Automatic Login**: Users are instantly logged in and redirected to the dashboard after successful email verification.
- **Organization Safety**: Max user limits are enforced at the model level based on the subscription tier (Basic: 5, Professional: 20).
- **Live Ingestion Safety**: Log readers track file offsets and deduplicate events before insert.
- **ML Security**: Trained models use joblib format (safer than pickle) with no external dependencies beyond scikit-learn.

---
