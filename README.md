# ThreatEye IDS

**Intelligent Intrusion Detection System with Machine Learning**

ThreatEye is a Django-based network intrusion detection system that captures network traffic, extracts features, and uses Random Forest classification to detect and categorize security threats in real-time.

---

## 🎯 Project Status

**Current Phase:** Authentication & Foundation (Complete ✅)  
**Next Phase:** Packet Capture & Feature Extraction

### Completed Features
- ✅ Email-based authentication system
- ✅ JWT token-based sessions (1-hour validity)
- ✅ Email verification with 6-digit codes (5-minute expiry)
- ✅ Admin-only user registration (Django Admin)
- ✅ React frontend with login/verification/dashboard flow
- ✅ Gmail SMTP integration with HTML email templates

### Planned Features
- 🔄 Packet capture layer (scapy/pyshark)
- 🔄 Feature extraction (packet_rate, port_count, failed_logins, ICMP analysis)
- 🔄 Rule-based pre-checks (port scanning, login abuse detection)
- 🔄 Random Forest ML classifier (SAFE/MEDIUM/HIGH threat levels)
- 🔄 Threat logging & auto-alerts
- 🔄 Dashboard with threat visualization
- 🔄 CSV/PDF report export

---

## 📋 Detailed Work Progress

### ✅ Phase 1: Authentication System (COMPLETE)

#### Backend Implementation
- [x] **Custom User Model** (`authentication/models.py`)
  - Email-based authentication (no username field)
  - UserManager for user/superuser creation
  - Email verification fields (is_verified, verification_code, code_expires_at)
  - Methods: `generate_verification_code()`, `verify_code()`
  - Password hashing: PBKDF2 with 260,000 iterations

- [x] **Django Admin Configuration** (`authentication/admin.py`)
  - Custom UserCreationForm with first_name requirement
  - Email format validation with domain checks
  - Admin can create users via Django Admin panel
  - Success/warning messages for email delivery status
  - Read-only fields: verification_code, code_expires_at, is_verified
  - List display: email, first_name, last_name, is_active, is_verified, date_joined

- [x] **API Endpoints** (`authentication/views.py`)
  - `POST /api/auth/login/` - Email/password authentication with JWT
  - `POST /api/auth/verify-email/` - Verify email with 6-digit code
  - `POST /api/auth/resend-verification/` - Generate new verification code
  - `POST /api/auth/logout/` - Logout (requires authentication)
  - `GET /api/auth/profile/` - Get authenticated user profile
  - All endpoints fully documented with docstrings

- [x] **Serializers** (`authentication/serializers.py`)
  - LoginSerializer: Email/password validation
  - UserSerializer: Profile data (excludes sensitive fields)
  - EmailVerificationSerializer: Code validation with expiry check
  - ResendVerificationSerializer: User eligibility check
  - Comprehensive validation logic with detailed error messages

- [x] **Email System** (`authentication/email_utils.py`)
  - Gmail SMTP integration (TLS on port 587)
  - HTML email templates with purple gradient design
  - Plain text fallback for email clients
  - Verification code display with expiry warning
  - Function: `send_verification_email(user)` returns bool

- [x] **Django Signals** (`authentication/signals.py`)
  - Auto-verify superusers (skip email verification)
  - Auto-send verification emails for regular users
  - Prevents duplicate emails when admin creates users
  - Handles API-created vs admin-created user workflows

- [x] **Database Migrations**
  - `0001_initial.py` - Initial User model creation
  - `0003_remove_user_email_sent.py` - Cleanup (removed tracking field)
  - All migrations applied successfully

#### Frontend Implementation
- [x] **React Components** (`Frontend/src/components/`)
  - `Login.jsx` - Email/password form with error handling
  - `EmailVerification.jsx` - 6-digit code input with auto-hide messages
  - `Dashboard.jsx` - User profile display with logout
  - Tailwind CSS styling (dark theme)
  - Loading states and disabled button logic

- [x] **Routing Logic** (`App.jsx`)
  - Conditional rendering based on auth state
  - Login → Verification (if not verified) → Dashboard flow
  - Token stored in memory (not localStorage for security)
  - User state management with useState hooks

- [x] **API Client** (`services/api.js`)
  - `login(email, password)` - Returns user + token
  - `getProfile(token)` - Fetches authenticated user data
  - Error handling with descriptive messages
  - Base URL: http://127.0.0.1:8000/api

- [x] **Styling** (`index.css`, `App.css`)
  - Tailwind CSS integration
  - Custom reset styles
  - Removed Vite default boilerplate
  - Responsive design for all screen sizes

#### Testing & Validation
- [x] User creation via Django Admin tested
- [x] Email delivery confirmed (Gmail SMTP)
- [x] Verification code generation and expiry working
- [x] Login flow tested (verified and unverified users)
- [x] JWT token generation validated (1-hour expiry)
- [x] Frontend routing tested (all user flows)
- [x] Error handling verified (invalid credentials, expired codes)
- [x] Auto-hide messages working (5-second timeout)

#### Documentation
- [x] Comprehensive docstrings in all Python modules
- [x] API endpoint documentation in views.py
- [x] Serializer validation logic documented
- [x] Email utility function documented
- [x] README created with setup instructions

### 🔄 Phase 2: Security Enhancements (PENDING)

#### Planned Tasks
- [ ] **Rate Limiting**
  - Prevent brute force login attempts (max 5 per IP per 5 min)
  - Limit verification code attempts (max 3 per email)
  - Limit resend verification requests (max 2 per 10 min)
  - Implementation: django-ratelimit or custom middleware

- [ ] **Audit Logging**
  - Log all login attempts (success/failure with IP, timestamp)
  - Log failed verification attempts
  - Track password change requests
  - Create AuditLog model with foreign key to User
  - Admin interface to view logs

- [ ] **Change Password Endpoint**
  - `POST /api/auth/change-password/`
  - Requires: current_password, new_password, new_password_confirm
  - Validates current password before allowing change
  - Sends confirmation email after password change

- [ ] **Testing Suite**
  - Unit tests for User model methods
  - API endpoint tests (DRF TestCase)
  - Serializer validation tests
  - Email sending mock tests
  - Frontend component tests (React Testing Library)

### 🔄 Phase 3: Packet Capture & Analysis (NOT STARTED)

#### Planned Tasks
- [ ] **Packet Capture Module**
  - Create `packet_capture/` Django app
  - Implement scapy-based live capture
  - Background service (Django management command)
  - Store raw packet metadata in database
  - Models: Packet (timestamp, src_ip, dst_ip, protocol, size, raw_data)

- [ ] **Feature Extraction Module**
  - Create `feature_extraction/` Django app
  - Extract: packet_rate, unique_port_count, avg_packet_size
  - Track: failed_login_attempts, icmp_frequency
  - Models: ExtractedFeatures (packet_id, feature_vector JSON)

- [ ] **Rule-Based Detection**
  - Port scanning detection (threshold: >10 unique ports/min)
  - Failed login detection (threshold: >5 failed logins/5 min)
  - ICMP flood detection (threshold: >100 ICMP packets/sec)
  - Add flags to feature vectors

### 🔄 Phase 4: Machine Learning (NOT STARTED)

#### Planned Tasks
- [ ] **Model Training**
  - Collect/generate sample network traffic dataset
  - Label data: SAFE, MEDIUM, HIGH threat levels
  - Train Random Forest classifier (scikit-learn)
  - Save model with joblib
  - Evaluate accuracy, precision, recall

- [ ] **ML Integration**
  - Create `ml_detection/` Django app
  - Load trained model at startup
  - Inference endpoint: classify feature vectors
  - Store predictions in database
  - Models: ThreatPrediction (features_id, threat_level, confidence)

### 🔄 Phase 5: Threat Management (NOT STARTED)

#### Planned Tasks
- [ ] **Threat Logging**
  - Models: ThreatLog (src_ip, protocol, threat_level, description, timestamp)
  - Auto-create logs after ML classification
  - Link to packet data for traceability

- [ ] **Alert System**
  - Models: Alert (threat_log_id, severity, acknowledged, created_at)
  - Auto-generate alerts for HIGH threat levels
  - Real-time updates via WebSockets or polling

- [ ] **Dashboard Visualization**
  - Threat count cards (SAFE/MEDIUM/HIGH)
  - Recent alerts feed (real-time)
  - Charts: Threat trends over time (Chart.js or Recharts)
  - Source IP analysis (top attackers)
  - Protocol distribution

### 🔄 Phase 6: Reporting (NOT STARTED)

#### Planned Tasks
- [ ] **CSV Export**
  - Export threat logs to CSV
  - Filter by date range, threat level, source IP
  - Download endpoint: `/api/reports/export/csv/`

- [ ] **PDF Generation**
  - Professional PDF reports (ReportLab or WeasyPrint)
  - Include: Summary stats, threat breakdown, top IPs
  - Download endpoint: `/api/reports/export/pdf/`

- [ ] **Scheduled Reports**
  - Django Celery integration for async tasks
  - Email daily/weekly reports to admins
  - Configurable report templates

---

## 🚧 Known Issues & Blockers

- None currently - Phase 1 complete and stable

---

## 📝 Development Notes

### Decisions Made
- **No password reset via email** - Security risk for compromised accounts; admin will handle resets
- **No refresh tokens** - Simpler architecture; 1-hour session acceptable for IDS use case
- **Email tracking removed** - Cleanup feature removed per user request; users always created even if email fails
- **Admin-only registration** - No public signup to maintain security control
- **JWT in memory** - Not in localStorage to prevent XSS attacks

### Environment Setup
- Backend runs on: http://127.0.0.1:8000
- Frontend runs on: http://localhost:5173
- Database: SQLite (development), MySQL (production planned)
- Email: Gmail SMTP (sharvikhadka@gmail.com)

---

## 🛠 Tech Stack

### Backend
- **Framework:** Django 5.2.8
- **API:** Django REST Framework 3.15.2
- **Authentication:** Simple JWT 5.4.0
- **Database:** MySQL (production) / SQLite (development)
- **Email:** Gmail SMTP with TLS

### Frontend
- **Framework:** React 19.2
- **Build Tool:** Vite 7.3
- **Styling:** Tailwind CSS

### ML & Analysis (Upcoming)
- **Packet Capture:** scapy / pyshark
- **ML Algorithm:** Random Forest (scikit-learn)
- **Model Storage:** joblib

---

## 📁 Project Structure

```
ThreatEye/
├── Backend/
│   ├── authentication/          # User auth & verification
│   │   ├── models.py           # Custom User model
│   │   ├── views.py            # API endpoints
│   │   ├── serializers.py      # DRF serializers
│   │   ├── admin.py            # Django admin config
│   │   ├── signals.py          # Auto-verification logic
│   │   ├── email_utils.py      # Email sending
│   │   └── urls.py             # Auth routes
│   ├── ThreatEye/              # Django project settings
│   │   ├── settings.py
│   │   └── urls.py
│   ├── manage.py
│   └── db.sqlite3
│
└── Frontend/
    ├── src/
    │   ├── components/
    │   │   ├── Login.jsx
    │   │   ├── EmailVerification.jsx
    │   │   └── Dashboard.jsx
    │   ├── services/
    │   │   └── api.js          # API client
    │   ├── App.jsx
    │   └── main.jsx
    └── package.json
```

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- MySQL (for production) or SQLite (development)
- Gmail account with App Password

### Backend Setup

1. **Clone & Navigate**
   ```bash
   cd Backend
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # Linux/Mac
   ```

3. **Install Dependencies**
   ```bash
   pip install django djangorestframework djangorestframework-simplejwt
   ```

4. **Configure Email (settings.py)**
   ```python
   EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
   EMAIL_HOST = 'smtp.gmail.com'
   EMAIL_PORT = 587
   EMAIL_USE_TLS = True
   EMAIL_HOST_USER = 'your-email@gmail.com'
   EMAIL_HOST_PASSWORD = 'your-app-password'  # Gmail App Password
   DEFAULT_FROM_EMAIL = 'your-email@gmail.com'
   ```

5. **Database Setup**
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

6. **Run Server**
   ```bash
   python manage.py runserver
   ```
   Backend: http://127.0.0.1:8000  
   Admin Panel: http://127.0.0.1:8000/admin

### Frontend Setup

1. **Navigate & Install**
   ```bash
   cd Frontend
   npm install
   ```

2. **Run Development Server**
   ```bash
   npm run dev
   ```
   Frontend: http://localhost:5173

---

## 📡 API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/login/` | Login with email/password | No |
| POST | `/api/auth/verify-email/` | Verify email with 6-digit code | No |
| POST | `/api/auth/resend-verification/` | Resend verification code | No |
| POST | `/api/auth/logout/` | Logout (clear token) | Yes |
| GET | `/api/auth/profile/` | Get user profile | Yes |

### Request/Response Examples

**Login:**
```bash
POST /api/auth/login/
{
  "email": "user@example.com",
  "password": "password123"
}

Response:
{
  "message": "Login successful",
  "user": {...},
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Verify Email:**
```bash
POST /api/auth/verify-email/
{
  "email": "user@example.com",
  "code": "123456"
}
```

---

## 👤 User Management

### Admin Panel
- Only **superadmins** can create users via Django Admin
- Users receive verification email automatically
- Required fields: email, first_name, password

### User Registration Flow
1. Admin creates user → System sends 6-digit code
2. User receives email with verification code
3. User logs in → Redirected to verification screen
4. User enters code → Access granted to dashboard

### Email Verification
- **Code Length:** 6 digits
- **Expiry:** 5 minutes
- **Format:** HTML + plain text
- **Delivery:** Gmail SMTP

---

## 🔒 Security Features

### Current Implementation
- **Password Hashing:** PBKDF2 (260,000 iterations)
- **JWT Tokens:** 1-hour validity, no refresh
- **Email Verification:** Mandatory for regular users
- **Admin-only Registration:** No public signup

### Planned Features
- Rate limiting (brute force protection)
- Audit logging (auth events tracking)
- Password change endpoint (user-initiated)
- Failed login monitoring

---

## 🧪 Testing

### Manual Testing
```bash
# Backend API tests
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "testpass"}'

# Frontend
npm run dev  # Test UI flow manually
```

### Future: Automated Tests
- Unit tests for models and serializers
- Integration tests for API endpoints
- E2E tests for user flows

---

## 📊 Database Schema (Current)

### User Model
| Field | Type | Description |
|-------|------|-------------|
| id | Integer | Primary key |
| email | EmailField | Unique, used for auth |
| password | CharField | Hashed (PBKDF2) |
| first_name | CharField | Required |
| last_name | CharField | Optional |
| is_verified | BooleanField | Email verification status |
| verification_code | CharField | 6-digit code |
| code_expires_at | DateTimeField | Code expiry timestamp |
| is_active | BooleanField | Account status |
| is_superuser | BooleanField | Admin privileges |
| date_joined | DateTimeField | Account creation date |

---

## 🗺 Development Roadmap

### Phase 1: Authentication ✅ (Complete)
- Custom User model with email auth
- JWT token system
- Email verification workflow
- React frontend UI

### Phase 2: Packet Capture (Next)
- Implement scapy/pyshark integration
- Background service for live capture
- Store raw packet metadata

### Phase 3: Feature Extraction
- Extract packet_rate, port_count, packet_size
- Track failed login attempts
- Monitor ICMP frequency
- Build feature vector for ML

### Phase 4: ML Integration
- Train Random Forest on sample data
- Integrate model inference into backend
- Classify threats (SAFE/MEDIUM/HIGH)

### Phase 5: Threat Management
- Threat logging system
- Auto-alert generation
- Dashboard visualization

### Phase 6: Reporting
- CSV export
- PDF generation
- Scheduled reports

---

## 🤝 Contributing

This is a Final Year Project (FYP). Collaboration guidelines:
- Follow existing code structure
- Write docstrings for all functions
- Test before committing
- No feature creep - stick to roadmap

---

## 📄 License

Educational project - ThreatEye IDS  
© 2025 All Rights Reserved

---

## 📞 Support

For issues or questions:
- Email: sharvikhadka@gmail.com
- Admin Panel: http://127.0.0.1:8000/admin

---

**Last Updated:** December 21, 2025  
**Version:** 0.1.0 (Authentication Phase)
