# MedSafe: Medication Management, Adherence & Safety Coordination Platform

A secure platform designed to verify medicine authenticity, track clinical adherence, coordinate healthcare workflows, and integrate medical payment processing.

---

## 🚀 Key Features & Capabilities

- **Clinical Adherence Rules Engine:** Automated dose tracking evaluating scheduled times against configurable grace periods (`GRACE_PERIOD_MINUTES=30`). Distinguishes `ON_TIME`, `LATE`, and `MISSED` doses in real time with calculated clinical compliance rates.
- **Secure JWT Authentication:** Role-Based Access Control (RBAC) supporting **Patients**, **Doctors**, **Receptionists**, and **Caregivers** using HMAC-SHA256 encrypted tokens (`JWT_SECRET`).
- **Payment Processing Infrastructure:** Complete Razorpay integration supporting dynamic order generation (`/api/payments/razorpay/create-order`) and cryptographic HMAC-SHA256 signature verification (`/api/payments/razorpay/verify-payment`).
- **Caregiver & Consent Coordination:** Authorized caregiver linking, consent scopes, and family delegation workflows.
- **Multi-Clinic & Provider Directory:** Centralized registry for doctors, clinics, hospitals, diagnostic labs, and consultation request routing.
- **Regulatory Audit Trail:** Automated immutable logging for sensitive actions (dose recorded, prescription created, payment verified, report accessed).
- **Interactive Web Dashboard:** Modern Tailwind CSS status dashboard and API explorer served at the root `/`.

---

## 🧰 Tech Stack

- **Backend Framework:** Python 3.11 / Flask 3.x
- **WSGI Production Server:** Gunicorn 21.x
- **Security & Tokens:** PyJWT / HMAC-SHA256
- **Storage Layer:** High-performance persistent JSON dataset store with SQLite support
- **Payment Gateway:** Razorpay API (Test & Live modes)
- **Deployment & Cloud:** Render (Native Python Web Service & Docker Containerization)

---

## 📂 Project Structure

```text
d:\Phase2\
├── .dockerignore              # Docker build exclusions
├── .env.example               # Example environment configuration
├── .gitignore                 # Git ignore rules
├── Dockerfile                 # Production Docker container configuration
├── Procfile                   # Render / Heroku process manager specification
├── README.md                  # Project documentation & deployment guide
├── app.py                     # Main Flask application & API routes
├── render.yaml                # Render Infrastructure-as-Code Blueprint
├── requirements.txt           # Python production dependencies
└── backend/
    └── data/                  # Persistent healthcare datasets
        ├── adherence_records.json
        ├── audit_logs.json
        ├── bills.json
        ├── caregivers.json
        ├── clinics.json
        ├── consents.json
        ├── consultation_requests.json
        ├── consultations.json
        ├── doctor_patient_relationships.json
        ├── doctors.json
        ├── follow_up_actions.json
        ├── labs.json
        ├── medical_reports.json
        ├── medications.json
        └── users.json
```

---

## 🌐 Deploying to Render

You can deploy MedSafe to [Render](https://render.com) using either of the following approaches:

### Method A: Render Web Service (Recommended)

1. **Commit and Push** this updated folder to your GitHub repository:
   ```bash
   git add .
   git commit -m "Add production Flask application and Render configuration"
   git push origin main
   ```
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** > **Web Service**.
3. Connect your GitHub repository (`ddsmanasa064-bit/MedSafe`).
4. Configure the service settings:
   - **Name:** `medsafe-platform`
   - **Environment:** `Python 3`
   - **Region:** `Oregon (US West)` or your preferred region
   - **Branch:** `main`
   - **Root Directory:** If you push the contents of `Phase2` directly into the repo, leave blank. If `Phase2` is a subfolder, set to `Phase2`.
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`
5. Under **Environment Variables**, add:
   - `FLASK_ENV`: `production`
   - `JWT_SECRET`: *(Click 'Generate' or enter a strong secret key)*
   - `GRACE_PERIOD_MINUTES`: `30`
   - `RAZORPAY_MODE`: `TEST`
   - `RAZORPAY_TEST_KEY_ID`: `rzp_test_MedSafeDemoKey123`
   - `RAZORPAY_TEST_KEY_SECRET`: `MedSafeSecretKey2026TestMode`
6. Click **Deploy Web Service**.

### Method B: Render Blueprint (`render.yaml`)

Because [render.yaml](file:///d:/Phase2/render.yaml) is included:
1. In Render Dashboard, click **New +** > **Blueprint**.
2. Select your repository. Render will automatically read `render.yaml`, configure the environment variables, and launch the service with zero manual configuration.

---

## 💻 Local Execution & Verification

### Running Locally with Python
```bash
# Install dependencies
pip install -r requirements.txt

# Start local server
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your browser.

### Running with Docker
```bash
# Build the Docker image
docker build -t medsafe-app .

# Run the container mapping port 5000
docker run -p 5000:5000 -e PORT=5000 medsafe-app
```

---

## 🧪 Testing Credentials

| Role | Email | Password |
| :--- | :--- | :--- |
| **Patient** | `anjali.sharma@medsafe.local` | `Password123!` |
| **Doctor** | `dr.ravi@medsafe.local` | `Password123!` |
| **Receptionist** | `receptionist.priya@medsafe.local` | `Password123!` |
| **Caregiver** | `caregiver.ramesh@medsafe.local` | `Password123!` |

---

## 📡 API Reference

- `GET /health` - Health check & diagnostic status
- `POST /api/auth/login` - User authentication (returns JWT)
- `GET /api/auth/me` - Authenticated user profile
- `GET /api/adherence` - Retrieve patient dose history
- `GET /api/adherence/stats` - Adherence percentage, on-time vs. late rates
- `POST /api/schedules/record-dose` - Record medication intake (evaluates grace period)
- `GET /api/medications` - Medication inventory & prescriptions
- `GET /api/doctors` - Directory of registered healthcare professionals
- `GET /api/bills` - Medical billing records
- `POST /api/payments/razorpay/create-order` - Generate Razorpay transaction order
- `POST /api/payments/razorpay/verify-payment` - Cryptographic payment verification
- `GET /api/audit-logs` - Regulatory compliance audit trail
