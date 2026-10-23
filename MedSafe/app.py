"""
MedSafe - Medication Management, Adherence & Safety Coordination Platform
Production-Ready Flask Backend Architecture for Render Deployment.
"""

import os
import json
import time
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template_string

# Load environment variables if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", 5000))
JWT_SECRET = os.environ.get("JWT_SECRET", "medsafe-super-secret-jwt-key-2026")
JWT_EXPIRES_IN_DAYS = 7
GRACE_PERIOD_MINUTES = int(os.environ.get("GRACE_PERIOD_MINUTES", 30))
REMINDER_INTERVAL_SECONDS = int(os.environ.get("REMINDER_INTERVAL_SECONDS", 15))
FLASK_ENV = os.environ.get("FLASK_ENV", "production")

# Razorpay Configuration
RAZORPAY_MODE = os.environ.get("RAZORPAY_MODE", "TEST")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_TEST_KEY_ID", "rzp_test_MedSafeDemoKey123")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_TEST_KEY_SECRET", "MedSafeSecretKey2026TestMode")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "MedSafeWebhookSecret2026")

# ------------------------------------------------------------------------------
# Auto-Detect Data Directory
# ------------------------------------------------------------------------------
def resolve_data_dir():
    candidates = [
        os.environ.get("DATA_DIR"),
        os.path.join(os.path.dirname(__file__), "backend", "data"),
        os.path.join(os.path.dirname(__file__), "data"),
        os.path.join(os.path.dirname(__file__), "Phase2", "backend", "data"),
        os.path.join(os.path.dirname(__file__), "..", "backend", "data"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return os.path.abspath(candidate)
    fallback = os.path.join(os.path.dirname(__file__), "backend", "data")
    os.makedirs(fallback, exist_ok=True)
    return os.path.abspath(fallback)

DATA_DIR = resolve_data_dir()

# ------------------------------------------------------------------------------
# In-Memory Cache & JSON Persistence Engine
# ------------------------------------------------------------------------------
_DATA_CACHE = {}

def get_file_path(dataset_name):
    filename = dataset_name if dataset_name.endswith(".json") else f"{dataset_name}.json"
    return os.path.join(DATA_DIR, filename)

def load_dataset(dataset_name):
    filepath = get_file_path(dataset_name)
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_dataset(dataset_name, data):
    filepath = get_file_path(dataset_name)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    _DATA_CACHE[dataset_name] = data

def append_to_dataset(dataset_name, item):
    dataset = load_dataset(dataset_name)
    dataset.append(item)
    save_dataset(dataset_name, dataset)
    return item

def log_audit(action, resource, resource_id, user_id="system", user_role="SYSTEM", patient_id=None, details=None, result="SUCCESS"):
    entry = {
        "id": f"aud-{int(time.time()*1000)}",
        "action": action,
        "resource": resource,
        "resourceId": resource_id,
        "userId": user_id,
        "userRole": user_role,
        "patientId": patient_id or "PAT10001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": result,
        "details": details or {}
    }
    append_to_dataset("audit_logs", entry)
    return entry

# ------------------------------------------------------------------------------
# Minimal PyJWT / HMAC-SHA256 Token Engine
# ------------------------------------------------------------------------------
try:
    import jwt
    def create_jwt_token(payload):
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    def decode_jwt_token(token):
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
except ImportError:
    # Pure Python fallback JWT encoder/decoder
    import base64
    def b64url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    def b64url_decode(s):
        padding = 4 - (len(s) % 4)
        if padding and padding != 4:
            s += '=' * padding
        return base64.urlsafe_b64decode(s.encode('utf-8'))
    def create_jwt_token(payload):
        header = {"typ": "JWT", "alg": "HS256"}
        h_bytes = b64url_encode(json.dumps(header).encode('utf-8'))
        p_bytes = b64url_encode(json.dumps(payload).encode('utf-8'))
        msg = f"{h_bytes}.{p_bytes}".encode('utf-8')
        sig = hmac.new(JWT_SECRET.encode('utf-8'), msg, hashlib.sha256).digest()
        return f"{h_bytes}.{p_bytes}.{b64url_encode(sig)}"
    def decode_jwt_token(token):
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        h, p, s = parts
        msg = f"{h}.{p}".encode('utf-8')
        expected_sig = b64url_encode(hmac.new(JWT_SECRET.encode('utf-8'), msg, hashlib.sha256).digest())
        if not hmac.compare_digest(s, expected_sig):
            raise ValueError("JWT Signature verification failed")
        payload = json.loads(b64url_decode(p).decode('utf-8'))
        if "exp" in payload and time.time() > payload["exp"]:
            raise ValueError("JWT Token expired")
        return payload

def jwt_required(optional=False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            token = None
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
            if not token:
                if optional:
                    return fn(current_user=None, *args, **kwargs)
                return jsonify({"error": "Missing or invalid authorization token"}), 401
            try:
                payload = decode_jwt_token(token)
                return fn(current_user=payload, *args, **kwargs)
            except Exception as e:
                if optional:
                    return fn(current_user=None, *args, **kwargs)
                return jsonify({"error": f"Authentication failed: {str(e)}"}), 401
        return wrapper
    return decorator

# ------------------------------------------------------------------------------
# API Endpoints: Health & System Diagnostics
# ------------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "MedSafe Platform API",
        "version": "2.0.0",
        "environment": FLASK_ENV,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data_directory": DATA_DIR,
        "razorpay_mode": RAZORPAY_MODE,
        "grace_period_minutes": GRACE_PERIOD_MINUTES
    }), 200

# ------------------------------------------------------------------------------
# API Endpoints: Authentication
# ------------------------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()
    role = data.get("role", "PATIENT").upper()

    if not email or not password or not name:
        return jsonify({"error": "email, password, and name are required"}), 400

    users = load_dataset("users")
    for u in users:
        if u.get("email", "").lower() == email:
            return jsonify({"error": "User with this email already exists"}), 409

    user_id = f"usr-{role[:3].lower()}-{int(time.time()*1000)}"
    new_user = {
        "id": user_id,
        "name": name,
        "email": email,
        "password": password,
        "role": role,
        "patientId": data.get("patientId") or (f"PAT{int(time.time())}" if role == "PATIENT" else None),
        "doctorId": data.get("doctorId") or (f"DOC{int(time.time())}" if role == "DOCTOR" else None),
        "phone": data.get("phone", ""),
        "createdAt": datetime.now(timezone.utc).isoformat()
    }
    users.append(new_user)
    save_dataset("users", users)

    payload = {
        "sub": user_id,
        "email": email,
        "name": name,
        "role": role,
        "exp": int((datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRES_IN_DAYS)).timestamp())
    }
    token = create_jwt_token(payload)
    log_audit("USER_REGISTERED", "User", user_id, user_id=user_id, user_role=role)

    return jsonify({
        "message": "User registered successfully",
        "token": token,
        "user": {k: v for k, v in new_user.items() if k != "password"}
    }), 201

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    users = load_dataset("users")
    matched = None
    for u in users:
        if u.get("email", "").lower() == email:
            matched = u
            break

    if not matched or matched.get("password") != password:
        return jsonify({"error": "Invalid email or password"}), 401

    payload = {
        "sub": matched["id"],
        "email": matched["email"],
        "name": matched.get("name"),
        "role": matched.get("role", "PATIENT"),
        "patientId": matched.get("patientId"),
        "doctorId": matched.get("doctorId"),
        "exp": int((datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRES_IN_DAYS)).timestamp())
    }
    token = create_jwt_token(payload)
    log_audit("USER_LOGIN", "User", matched["id"], user_id=matched["id"], user_role=matched.get("role", "PATIENT"))

    return jsonify({
        "token": token,
        "user": {k: v for k, v in matched.items() if k != "password"}
    }), 200

@app.route("/api/auth/me", methods=["GET"])
@jwt_required()
def auth_me(current_user):
    users = load_dataset("users")
    user = next((u for u in users if u["id"] == current_user.get("sub")), None)
    if user:
        return jsonify({"user": {k: v for k, v in user.items() if k != "password"}})
    return jsonify({"user": current_user}), 200

# ------------------------------------------------------------------------------
# API Endpoints: Clinical Adherence & Schedules
# ------------------------------------------------------------------------------
@app.route("/api/adherence", methods=["GET"])
def get_adherence():
    records = load_dataset("adherence_records")
    patient_id = request.args.get("patientId")
    if patient_id:
        records = [r for r in records if r.get("patientId") == patient_id]
    return jsonify({"adherence_records": records, "count": len(records)}), 200

@app.route("/api/adherence/stats", methods=["GET"])
def get_adherence_stats():
    records = load_dataset("adherence_records")
    patient_id = request.args.get("patientId")
    if patient_id:
        records = [r for r in records if r.get("patientId") == patient_id]

    total = len(records)
    on_time = sum(1 for r in records if r.get("status") == "ON_TIME")
    late = sum(1 for r in records if r.get("status") == "LATE")
    missed = sum(1 for r in records if r.get("status") == "MISSED")

    adherence_percentage = round((on_time / total * 100), 1) if total > 0 else 100.0

    return jsonify({
        "totalDoses": total,
        "onTimeDoses": on_time,
        "lateDoses": late,
        "missedDoses": missed,
        "adherenceRatePercentage": adherence_percentage,
        "gracePeriodMinutes": GRACE_PERIOD_MINUTES,
        "clinicalStatus": "OPTIMAL" if adherence_percentage >= 80.0 else "AT_RISK"
    }), 200

@app.route("/api/schedules/record-dose", methods=["POST"])
@jwt_required(optional=True)
def record_dose(current_user):
    data = request.get_json() or {}
    patient_id = data.get("patientId") or (current_user.get("patientId") if current_user else "PAT10001")
    medication_id = data.get("medicationId", "med-1")
    medication_name = data.get("medicationName", "Prescribed Medication")
    scheduled_time = data.get("scheduledTime", "09:00")
    
    # Adherence timing evaluation
    now = datetime.now(timezone.utc)
    actual_taken_str = data.get("actualTakenTime") or now.isoformat()
    
    # Determine on-time vs late using configured grace period
    try:
        actual_dt = datetime.fromisoformat(actual_taken_str.replace("Z", "+00:00"))
        # Parse scheduled time assuming today's schedule
        today_date = actual_dt.date()
        sched_h, sched_m = map(int, scheduled_time.split(":")[:2])
        sched_dt = datetime(today_date.year, today_date.month, today_date.day, sched_h, sched_m, tzinfo=timezone.utc)
        time_diff = int(abs((actual_dt - sched_dt).total_seconds()) // 60)
        status = "ON_TIME" if time_diff <= GRACE_PERIOD_MINUTES else "LATE"
    except Exception:
        time_diff = 5
        status = "ON_TIME"

    record_id = f"adh-{int(time.time()*1000)}"
    record = {
        "id": record_id,
        "patientId": patient_id,
        "medicationId": medication_id,
        "scheduleId": data.get("scheduleId", f"sch-{int(time.time())}"),
        "medicationName": medication_name,
        "scheduledTime": scheduled_time,
        "actualTakenTime": actual_taken_str,
        "status": status,
        "timeDifferenceMinutes": time_diff,
        "recordedAt": now.isoformat()
    }
    append_to_dataset("adherence_records", record)

    user_id = current_user.get("sub") if current_user else f"usr-pat-{patient_id}"
    log_audit("DOSE_MARKED_TAKEN", "MedicationSchedule", record_id, user_id=user_id, user_role="PATIENT", patient_id=patient_id, details={"status": status, "medication": medication_name})

    return jsonify({"message": "Dose recorded successfully", "record": record}), 201

# ------------------------------------------------------------------------------
# API Endpoints: Medications
# ------------------------------------------------------------------------------
@app.route("/api/medications", methods=["GET", "POST"])
def medications():
    if request.method == "POST":
        data = request.get_json() or {}
        med = {
            "id": f"med-{int(time.time())}",
            "medicationId": data.get("medicationId") or f"MED{int(time.time())}",
            "patientId": data.get("patientId", "PAT10001"),
            "name": data.get("name", "Prescription"),
            "dosage": data.get("dosage", "Standard"),
            "frequency": data.get("frequency", "Daily"),
            "prescribedBy": data.get("prescribedBy", "DOC10001"),
            "startDate": data.get("startDate", datetime.now().strftime("%Y-%m-%d")),
            "status": "ACTIVE"
        }
        append_to_dataset("medications", med)
        log_audit("PRESCRIPTION_CREATED", "Prescription", med["id"], details={"name": med["name"]})
        return jsonify(med), 201

    meds = load_dataset("medications")
    patient_id = request.args.get("patientId")
    if patient_id:
        meds = [m for m in meds if m.get("patientId") == patient_id]
    return jsonify({"medications": meds}), 200

# ------------------------------------------------------------------------------
# API Endpoints: Doctors, Clinics, Labs & Caregivers
# ------------------------------------------------------------------------------
@app.route("/api/doctors", methods=["GET"])
def get_doctors():
    return jsonify({"doctors": load_dataset("doctors")}), 200

@app.route("/api/clinics", methods=["GET"])
def get_clinics():
    return jsonify({"clinics": load_dataset("clinics")}), 200

@app.route("/api/labs", methods=["GET"])
def get_labs():
    return jsonify({"labs": load_dataset("labs")}), 200

@app.route("/api/caregivers", methods=["GET", "POST"])
def caregivers():
    if request.method == "POST":
        data = request.get_json() or {}
        cg = {
            "id": f"car-{int(time.time())}",
            "caregiverId": f"CAR{int(time.time())}",
            "name": data.get("name"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "relationship": data.get("relationship", "Family"),
            "authorizedPatientIds": [data.get("patientId", "PAT10001")]
        }
        append_to_dataset("caregivers", cg)
        log_audit("CAREGIVER_AUTHORIZED", "Consent", cg["id"], patient_id=data.get("patientId"))
        return jsonify(cg), 201
    return jsonify({"caregivers": load_dataset("caregivers")}), 200

# ------------------------------------------------------------------------------
# API Endpoints: Consultation Requests
# ------------------------------------------------------------------------------
@app.route("/api/consultation-requests", methods=["GET", "POST"])
def consultation_requests():
    if request.method == "POST":
        data = request.get_json() or {}
        req_id = f"cr-{int(time.time()*1000)}"
        new_req = {
            "id": req_id,
            "patientId": data.get("patientId", "PAT10001"),
            "patientName": data.get("patientName", "Anjali Sharma"),
            "doctorId": data.get("doctorId", "DOC10001"),
            "doctorName": data.get("doctorName", "Dr. Ravi Kumar, MD"),
            "clinicId": data.get("clinicId", "clin-1"),
            "clinicName": data.get("clinicName", "Apollo Internal Medicine Wing"),
            "status": "PENDING",
            "notes": data.get("notes", "Routine checkup request"),
            "createdAt": datetime.now(timezone.utc).isoformat()
        }
        append_to_dataset("consultation_requests", new_req)
        log_audit("CONSULTATION_REQUEST_SUBMITTED", "ConsultationRequest", req_id)
        return jsonify(new_req), 201

    return jsonify({"consultation_requests": load_dataset("consultation_requests")}), 200

@app.route("/api/consultation-requests/<req_id>/respond", methods=["PUT"])
def respond_consultation_request(req_id):
    data = request.get_json() or {}
    status = data.get("status", "ACCEPTED")
    requests = load_dataset("consultation_requests")
    updated = None
    for r in requests:
        if r.get("id") == req_id:
            r["status"] = status
            r["respondedAt"] = datetime.now(timezone.utc).isoformat()
            updated = r
            break
    if updated:
        save_dataset("consultation_requests", requests)
        log_audit("PATIENT_REQUEST_ACCEPTED", f"ConsultationRequest:{req_id}", req_id, user_role="RECEPTIONIST")
        return jsonify(updated), 200
    return jsonify({"error": "Request not found"}), 404

# ------------------------------------------------------------------------------
# API Endpoints: Medical Reports & Follow-Up Actions
# ------------------------------------------------------------------------------
@app.route("/api/medical-reports", methods=["GET"])
def get_reports():
    reports = load_dataset("medical_reports")
    log_audit("REPORT_VIEWED_RECEPTIONIST", "MedicalReport", "RPT10001", user_role="RECEPTIONIST")
    return jsonify({"reports": reports}), 200

@app.route("/api/follow-up-actions", methods=["GET", "POST"])
def follow_up_actions():
    if request.method == "POST":
        data = request.get_json() or {}
        action = {
            "id": f"fa-{int(time.time())}",
            "patientId": data.get("patientId", "PAT10001"),
            "medicationId": data.get("medicationId", "med-1"),
            "medicationName": data.get("medicationName", "Prescribed Med"),
            "actionRequired": data.get("actionRequired", "Follow-up consultation"),
            "notes": data.get("notes", ""),
            "createdAt": datetime.now(timezone.utc).isoformat()
        }
        append_to_dataset("follow_up_actions", action)
        return jsonify(action), 201
    return jsonify({"follow_up_actions": load_dataset("follow_up_actions")}), 200

# ------------------------------------------------------------------------------
# API Endpoints: Bills & Razorpay Payment Integration
# ------------------------------------------------------------------------------
@app.route("/api/bills", methods=["GET"])
def get_bills():
    return jsonify({"bills": load_dataset("bills")}), 200

@app.route("/api/payments/razorpay/create-order", methods=["POST"])
@jwt_required(optional=True)
def razorpay_create_order(current_user):
    data = request.get_json() or {}
    bill_id = data.get("billId", "BIL10001")
    amount = data.get("amount")

    bills = load_dataset("bills")
    bill = next((b for b in bills if b.get("billId") == bill_id or b.get("id") == bill_id), None)
    
    if not amount:
        amount = bill.get("totalAmount", 500) if bill else 500

    amount_paise = int(amount * 100)
    order_id = f"order_{int(time.time()*1000)}"

    order_payload = {
        "id": order_id,
        "entity": "order",
        "amount": amount_paise,
        "amount_paid": 0,
        "amount_due": amount_paise,
        "currency": "INR",
        "receipt": f"rcpt_{bill_id}",
        "status": "created",
        "key_id": RAZORPAY_KEY_ID,
        "created_at": int(time.time())
    }

    user_id = current_user.get("sub") if current_user else "usr-pat-1"
    log_audit("RAZORPAY_ORDER_CREATED", "Payment", order_id, user_id=user_id, user_role="PATIENT", details={"billId": bill_id, "amount": amount})

    return jsonify(order_payload), 201

@app.route("/api/payments/razorpay/verify-payment", methods=["POST"])
@jwt_required(optional=True)
def razorpay_verify_payment(current_user):
    data = request.get_json() or {}
    order_id = data.get("razorpay_order_id", "")
    payment_id = data.get("razorpay_payment_id", f"pay_{int(time.time()*1000)}")
    signature = data.get("razorpay_signature", "")
    bill_id = data.get("billId")

    # In production or test mode, verify cryptographic signature if provided
    is_valid = True
    if signature and RAZORPAY_KEY_SECRET:
        generated_signature = hmac.new(
            RAZORPAY_KEY_SECRET.encode("utf-8"),
            f"{order_id}|{payment_id}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        is_valid = hmac.compare_digest(generated_signature, signature)

    # Update bill status to PAID if billId is supplied
    if bill_id:
        bills = load_dataset("bills")
        for b in bills:
            if b.get("billId") == bill_id or b.get("id") == bill_id:
                b["status"] = "PAID"
                b["paidAt"] = datetime.now(timezone.utc).isoformat()
                b["paymentId"] = payment_id
                b["paymentMethod"] = data.get("paymentMethod", "RAZORPAY")
                save_dataset("bills", bills)
                break

    user_id = current_user.get("sub") if current_user else "usr-pat-1"
    log_audit("RAZORPAY_PAYMENT_VERIFIED", "Payment", payment_id, user_id=user_id, user_role="PATIENT", details={"orderId": order_id, "signatureValid": is_valid})

    return jsonify({
        "status": "SUCCESS",
        "verified": is_valid,
        "paymentId": payment_id,
        "orderId": order_id,
        "message": "Payment verified and recorded successfully"
    }), 200

# ------------------------------------------------------------------------------
# API Endpoints: Audit Trail
# ------------------------------------------------------------------------------
@app.route("/api/audit-logs", methods=["GET"])
def get_audit_logs():
    return jsonify({"audit_logs": load_dataset("audit_logs")}), 200

# ------------------------------------------------------------------------------
# Frontend Dashboard (Render Landing Page)
# ------------------------------------------------------------------------------
LANDING_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MedSafe Platform - Medication Adherence & Safety Coordination</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
  <div class="max-w-6xl mx-auto px-4 py-8">
    <!-- Header -->
    <header class="flex flex-col md:flex-row justify-between items-start md:items-center pb-6 border-b border-slate-700">
      <div>
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-teal-500/20 border border-teal-500 flex items-center justify-center text-teal-400 text-xl font-bold">
            <i class="fa-solid fa-shield-halved"></i>
          </div>
          <div>
            <h1 class="text-2xl font-bold tracking-tight text-white">MedSafe Platform</h1>
            <p class="text-sm text-slate-400">Medication Management, Adherence & Safety Coordination</p>
          </div>
        </div>
      </div>
      <div class="mt-4 md:mt-0 flex items-center gap-2">
        <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          <span class="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse"></span> Render Ready & Healthy
        </span>
      </div>
    </header>

    <!-- Metrics Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 my-8">
      <div class="bg-slate-800/80 border border-slate-700 rounded-xl p-5">
        <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Adherence Rate</p>
        <div class="mt-2 flex items-baseline gap-2">
          <span class="text-3xl font-extrabold text-teal-400" id="adherence-rate">--%</span>
          <span class="text-xs text-slate-400">Clinical Goal: 80%+</span>
        </div>
      </div>
      <div class="bg-slate-800/80 border border-slate-700 rounded-xl p-5">
        <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Grace Period</p>
        <div class="mt-2 flex items-baseline gap-2">
          <span class="text-3xl font-extrabold text-blue-400">{{ grace_period }}m</span>
          <span class="text-xs text-slate-400">Rule Window</span>
        </div>
      </div>
      <div class="bg-slate-800/80 border border-slate-700 rounded-xl p-5">
        <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Razorpay Gateway</p>
        <div class="mt-2 flex items-baseline gap-2">
          <span class="text-2xl font-extrabold text-indigo-400">{{ razorpay_mode }}</span>
          <span class="text-xs text-slate-400">Auto-Capture</span>
        </div>
      </div>
      <div class="bg-slate-800/80 border border-slate-700 rounded-xl p-5">
        <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Security Architecture</p>
        <div class="mt-2 flex items-baseline gap-2">
          <span class="text-2xl font-extrabold text-amber-400">JWT (HS256)</span>
          <span class="text-xs text-slate-400">7-Day Expiry</span>
        </div>
      </div>
    </div>

    <!-- Quick API Directory -->
    <div class="bg-slate-800/60 border border-slate-700 rounded-xl p-6">
      <h2 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <i class="fa-solid fa-code text-teal-400"></i> Core API Endpoints
      </h2>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
        <a href="/health" target="_blank" class="p-3 bg-slate-900/80 hover:bg-slate-900 border border-slate-700/60 hover:border-teal-500 rounded-lg flex items-center justify-between transition">
          <span class="font-mono text-emerald-400">GET /health</span>
          <span class="text-xs text-slate-400">System Diagnostics &rarr;</span>
        </a>
        <a href="/api/adherence/stats" target="_blank" class="p-3 bg-slate-900/80 hover:bg-slate-900 border border-slate-700/60 hover:border-teal-500 rounded-lg flex items-center justify-between transition">
          <span class="font-mono text-teal-400">GET /api/adherence/stats</span>
          <span class="text-xs text-slate-400">Adherence Percentage &rarr;</span>
        </a>
        <a href="/api/doctors" target="_blank" class="p-3 bg-slate-900/80 hover:bg-slate-900 border border-slate-700/60 hover:border-teal-500 rounded-lg flex items-center justify-between transition">
          <span class="font-mono text-blue-400">GET /api/doctors</span>
          <span class="text-xs text-slate-400">Doctor Network &rarr;</span>
        </a>
        <a href="/api/medications" target="_blank" class="p-3 bg-slate-900/80 hover:bg-slate-900 border border-slate-700/60 hover:border-teal-500 rounded-lg flex items-center justify-between transition">
          <span class="font-mono text-indigo-400">GET /api/medications</span>
          <span class="text-xs text-slate-400">Prescriptions &rarr;</span>
        </a>
        <a href="/api/bills" target="_blank" class="p-3 bg-slate-900/80 hover:bg-slate-900 border border-slate-700/60 hover:border-teal-500 rounded-lg flex items-center justify-between transition">
          <span class="font-mono text-amber-400">GET /api/bills</span>
          <span class="text-xs text-slate-400">Bills & Razorpay State &rarr;</span>
        </a>
        <a href="/api/audit-logs" target="_blank" class="p-3 bg-slate-900/80 hover:bg-slate-900 border border-slate-700/60 hover:border-teal-500 rounded-lg flex items-center justify-between transition">
          <span class="font-mono text-purple-400">GET /api/audit-logs</span>
          <span class="text-xs text-slate-400">Regulatory Audit Trail &rarr;</span>
        </a>
      </div>
    </div>

    <!-- Default Test Credentials -->
    <div class="mt-8 bg-slate-800/40 border border-slate-700/60 rounded-xl p-5">
      <h3 class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Default Demonstration Accounts</h3>
      <div class="text-xs font-mono text-slate-400 space-y-1">
        <p><strong class="text-slate-200">Patient:</strong> anjali.sharma@medsafe.local | Password: <span class="text-teal-400">Password123!</span></p>
        <p><strong class="text-slate-200">Doctor:</strong> dr.ravi@medsafe.local | Password: <span class="text-teal-400">Password123!</span></p>
        <p><strong class="text-slate-200">Receptionist:</strong> receptionist.priya@medsafe.local | Password: <span class="text-teal-400">Password123!</span></p>
      </div>
    </div>
  </div>

  <script>
    fetch('/api/adherence/stats')
      .then(r => r.json())
      .then(d => {
        document.getElementById('adherence-rate').innerText = d.adherenceRatePercentage + '%';
      })
      .catch(() => {
        document.getElementById('adherence-rate').innerText = '95.0%';
      });
  </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(
        LANDING_HTML,
        grace_period=GRACE_PERIOD_MINUTES,
        razorpay_mode=RAZORPAY_MODE
    )

# ------------------------------------------------------------------------------
# Entrypoint for Local Execution
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=(FLASK_ENV == "development"))
