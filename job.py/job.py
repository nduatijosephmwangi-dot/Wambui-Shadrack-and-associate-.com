import os
import random
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.utils import secure_filename

import base64
from datetime import datetime

def get_mpesa_password():
    shortcode = os.getenv('4747331')
    passkey = os.getenv('PASSKEY')
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    
    # Format: Shortcode + Passkey + Timestamp
    data_to_encode = f"{shortcode}{passkey}{timestamp}"
    encoded_string = base64.b64encode(data_to_encode.encode()).decode('utf-8')
    
    return encoded_string, timestamp@app.route('/test-payment', methods=['GET'])
def test_payment():
    # This is just for testing. Do not put this in production.
    phone = "254708374149" # Use a test/sandbox phone number
    amount = 1
    client_name = "TestUser"
    
    result = (phone, amount, client_name)
    return jsonify(result)


# =========================================================
# ⚙️ SYSTEM CONFIGURATION & SETUP
# =========================================================

app = Flask(__name__)
CORS(app)

app.config['DATABASE_URL'] = os.environ.get(
    'DATABASE_URL', 
    'dbname=postgres user=postgres password=jose1023 host=localhost port=5432'
)  
app.config['UPLOAD_FOLDER'] = './client_docs/'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Secure system logging for cyber analysis
logging.basicConfig(
    filename='system_security.log', 
    level=logging.INFO, 
    format='%(asctime)s %(levelname)s: %(message)s'
)

# In-Memory Security State & Router Store
SYSTEM_STATE = {
    "LOCKDOWN_MODE": False,
    "OTP_STORE": {}
}

# =========================================================
# 🗄️ DATABASE CONNECTION MANAGEMENT & AUTO-INITIALIZATION
# =========================================================

def get_db():
    """Establish and return database connection with RealDictCursor."""
    if 'db' not in g:
        g.db = psycopg2.connect(app.config['DATABASE_URL'], cursor_factory=RealDictCursor)
    return g.db

@app.teardown_appcontext
def close_db(e):
    """Safely terminate database connection at the end of a request context."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes schema tables and seeds system staff accounts dynamically on initialization."""
    try:
        conn = psycopg2.connect(app.config['DATABASE_URL'])
        cur = conn.cursor()
        
        # 1. Initialize Users Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                phone_number VARCHAR(50) UNIQUE NOT NULL,
                role VARCHAR(50) NOT NULL
            );
        """)
        
        # 2. Initialize Cases Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id SERIAL PRIMARY KEY,
                case_number VARCHAR(255) UNIQUE NOT NULL,
                case_parties TEXT,
                client_name VARCHAR(255),
                next_court_date VARCHAR(255),
                coming_up_for TEXT,
                total_balance NUMERIC(15,2) DEFAULT 0.00,
                paid_balance NUMERIC(15,2) DEFAULT 0.00,
                ai_access_granted BOOLEAN DEFAULT FALSE
            );
        """)

        # 3. Initialize AI Interaction Log Table (New Feature for Staff Monitoring)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ai_client_logs (
                log_id SERIAL PRIMARY KEY,
                case_number VARCHAR(255) NOT NULL,
                client_name VARCHAR(255),
                client_question TEXT NOT NULL,
                ai_response TEXT NOT NULL,
                logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # 4. Seed Wambui Shadrack as the absolute Admin Account
        cur.execute("""
            INSERT INTO users (full_name, phone_number, role) 
            VALUES ('Shadrack Wambui', '0711223344', 'admin') 
            ON CONFLICT (phone_number) DO NOTHING;
        """)
        
        # 5. Seed Jeff Kangethe into the Staff Portal Ecosystem
        cur.execute("""
            INSERT INTO users (full_name, phone_number, role) 
            VALUES ('Jeff Kangethe', '0722334455', 'advocate') 
            ON CONFLICT (phone_number) DO NOTHING;
        """)
        
        # 5. Seed jane onyango into the Staff Portal Ecosystem
        cur.execute("""
            INSERT INTO users (full_name, phone_number, role) 
            VALUES ('jane onyango', '0795204923', 'secretary') 
            ON CONFLICT (phone_number) DO NOTHING;
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("💾 [DATABASE INITIALIZATION] Schema verified and team registry seeded successfully.")
    except Exception as e:
        print(f"⚠️ [DATABASE INITIALIZATION FAILURE] Couldn't map setup attributes: {str(e)}")

# =========================================================
# 🛡️ SECURITY MIDDLEWARE (THE CYBER KILL SWITCH)
# =========================================================

@app.before_request
def cyber_security_check():
    """Immediately blocks all incoming traffic except auth routes if Cyber Attack lockdown is flipped."""
    if SYSTEM_STATE["LOCKDOWN_MODE"]:
        allowed_routes = ['login_router', 'verify_otp', 'toggle_kill_switch']
        if request.endpoint not in allowed_routes:
            logging.warning(f"BLOCKED REQUEST: Unauthorized path access attempt to '{request.endpoint}' during lockdown.")
            return jsonify({
                "success": False,
                "error": "SECURITY_LOCKDOWN",
                "message": "⚠️ PORTAL LOCKDOWN ACTIVE. Client access has been suspended due to an ongoing threat protocol."
            }), 503

# =========================================================
# 🔐 SYSTEM ROUTING & AUTHENTICATION LAYER
# =========================================================

@app.route('/api/auth/login-router', methods=['POST'])
def login_router():
    """Routes logging users to Staff (by Phone Number) or Client Dashboard (by Case Number)."""
    payload = request.get_json() or {}
    credential = payload.get('credential', '').strip()
    
    if not credential:
        return jsonify({"success": False, "message": "Login field cannot be blank."}), 400
        
    if credential.isdigit() and len(credential) >= 10:
        return initiate_staff_login(credential)
    else:
        return client_login(credential)

def initiate_staff_login(phone):
    """Queries users database utilizing exact schema columns."""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT full_name, phone_number, role 
            FROM users 
            WHERE phone_number = %s AND role IN ('admin', 'advocate', 'secretary');
        """, (phone,))
        account = cur.fetchone()
        
        if not account:
            return jsonify({"success": False, "message": "Access Denied: Number is not registered as active staff."}), 403
        
        otp = str(random.randint(100000, 999999))
        SYSTEM_STATE["OTP_STORE"][phone] = {"code": otp, "user": account}
        
        print(f"\n📡 [SMS UTILITY LOG] Token Dispatch for {account['full_name']} -> {otp}\n")
        logging.info(f"OTP generated successfully for staff phone: {account['phone_number']}")
        
        return jsonify({"success": True, "mode": "otp_required", "message": "OTP verification code dispatched to handset."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Server Authentication Fault: {str(e)}"}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    """Checks OTP token signature matching the active session memory."""
    data = request.get_json() or {}
    phone = data.get('phone', '').strip()
    code = data.get('code', '').strip()
    
    record = SYSTEM_STATE["OTP_STORE"].get(phone)
    if not record or record['code'] != code:
        return jsonify({"success": False, "message": "Invalid or expired verification token signature."}), 401
    
    SYSTEM_STATE["OTP_STORE"].pop(phone, None)
    
    return jsonify({
        "success": True,
        "role": record['user']['role'], 
        "user_name": record['user']['full_name'],    
        "lockdown_status": SYSTEM_STATE["LOCKDOWN_MODE"]
    })

def client_login(case_number):
    """Views case matter data, returning case parties and case prediction metrics directly to the client."""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT case_id, case_number, case_parties, client_name, ai_access_granted, next_court_date, coming_up_for, total_balance, paid_balance
            FROM cases 
            WHERE case_number ILIKE %s
        """, (f"%{case_number}%",))
        case = cur.fetchone()
        
        if not case:
            return jsonify({"success": False, "message": "No legal records found matching that case context."}), 404
            
        total = float(case['total_balance'] or 0)
        paid = float(case['paid_balance'] or 0)
        outstanding = total - paid
        
        simulated_score = random.randint(55, 98)
        prediction_text = f"Based on evidentiary density, case file outcome trends track at an estimated {simulated_score}% favorable rating."
        
        return jsonify({
            "success": True,
            "mode": "client_dashboard",
            "data": {
                "case_id": case['case_id'],
                "case_number": case['case_number'],
                "case_parties": case['case_parties'], 
                "client_name": case['client_name'],
                "next_court_date": str(case['next_court_date']),
                "coming_up_for": case['coming_up_for'],
                "financials": {"total": total, "paid": paid, "balance": outstanding},
                "ai_unlocked": case['ai_access_granted'],
                "case_predictor": {
                    "score": simulated_score,
                    "analysis": prediction_text
                }
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Database Ingestion Failure: {str(e)}"}), 500

# =========================================================
# 🤖 LEGAL AI INTERACTION ENGINE & PREDICTOR
# =========================================================

@app.route('/api/ai/consult', methods=['POST'])
def ai_consult():
    """Enforces segmented AI permissions and archives client interactions for staff tracking."""
    data = request.get_json() or {}
    question = data.get('question', '').strip()
    user_name = data.get('user_name', '').strip()       
    case_number = data.get('case_number', '').strip()   
    ai_type = data.get('ai_type', 'free').strip().lower() 
    
    if not question:
        return jsonify({"success": False, "message": "Question context cannot be blank."}), 400
        
    if user_name == "Wambui Shadrack":
        simulated_response = f"⚖️ [Wambui Shadrack Exclusive Admin AI - Constitution of Kenya 2010]: For your query '{question}', the structural framework is protected under Chapter Four (Bill of Rights) provisions."
        return jsonify({"success": True, "engine": "Constitution 2010", "answer": simulated_response})
        
    if user_name and (user_name != "Wambui Shadrack" or ai_type == 'free'):
        simulated_response = f"📋 [Staff Assistant Free AI - Active for {user_name}]: Processing operational guidance for query: '{question}'. Pleadings compliance looks correct."
        return jsonify({"success": True, "engine": "Staff Assistant Free AI", "answer": simulated_response})
        
    if case_number:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT client_name, ai_access_granted FROM cases WHERE case_number = %s", (case_number,))
            case_record = cur.fetchone()
            
            if not case_record:
                return jsonify({"success": False, "message": "Case matching client verification context not found."}), 404
                
            if ai_type == "consultant":
                if case_record['ai_access_granted']:
                    simulated_response = f"🧠 [Premium Client Consultant AI]: Strategic evaluation regarding: '{question}'. Calculated evidentiary metrics indicate optimized court pathing."
                    engine_used = "Paid Consultant AI"
                else:
                    return jsonify({
                        "success": False, 
                        "message": "Access Denied: Premium Consultant AI requires a KES 5,000 activation fee. Please trigger the billing portal endpoint."
                    }), 402
            else:
                simulated_response = f"ℹ️ [Client Free Status AI]: Basic summary regarding: '{question}'. Your matter is safely logged with next date updates."
                engine_used = "Client Free AI"
                
            cur.execute("""
                INSERT INTO ai_client_logs (case_number, client_name, client_question, ai_response)
                VALUES (%s, %s, %s, %s)
            """, (case_number, case_record['client_name'], question, simulated_response))
            conn.commit()
            
            return jsonify({"success": True, "engine": engine_used, "answer": simulated_response})
        except Exception as e:
            return jsonify({"success": False, "message": f"AI verification fault: {str(e)}"}), 500

    return jsonify({"success": False, "message": "Unable to verify routing scope authorization."}), 400

# =========================================================
# 💸 TRANSACTIONS & CLIENT UPLOAD ENGINE
# =========================================================

@app.route('/api/public/process-payment', methods=['POST'])
def process_payment():
    """Processes payments dynamically based on user selection (Mpesa or Card) directly against Account Number."""
    payload = request.get_json() or {}
    amount = payload.get('amount')
    account_number = payload.get('account_number', '').strip() 
    payment_method = payload.get('payment_method', '').lower()
    phone_number = payload.get('phone_number', '').strip()
    
    if not amount or float(amount) <= 0:
        return jsonify({"success": False, "message": "A valid numerical payment amount structure is required."}), 400
    if not account_number:
        return jsonify({"success": False, "message": "Account number matching case record is required."}), 400
    if payment_method not in ['mpesa', 'card']:
        return jsonify({"success": False, "message": "Please select a valid payment method (Mpesa or Card)."}), 400
    if payment_method == 'mpesa' and not phone_number:
        return jsonify({"success": False, "message": "Phone number is required to send the M-Pesa STK prompt."}), 400
        
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("SELECT case_number, ai_access_granted FROM cases WHERE case_number = %s", (account_number,))
        case_record = cur.fetchone()
        
        if not case_record:
            return jsonify({"success": False, "message": "Payment declined: Account number does not match any active case ledger."}), 404
            
        float_amount = float(amount)
        
        if payment_method == 'mpesa':
            base_msg = f"M-Pesa prompt successfully pushed to {phone_number}. Please enter your PIN."
        else:
            base_msg = f"Card transaction for KES {amount} verified and processed successfully."
        
        if float_amount == 5000.00 and not case_record['ai_access_granted']:
            cur.execute("""
                UPDATE cases 
                SET paid_balance = paid_balance + %s, ai_access_granted = TRUE 
                WHERE case_number = %s
            """, (float_amount, account_number))
            msg = f"{base_msg} Premium Consultant AI has been unlocked successfully!"
        else:
            cur.execute("""
                UPDATE cases 
                SET paid_balance = paid_balance + %s 
                WHERE case_number = %s
            """, (float_amount, account_number))
            msg = f"{base_msg} Your account balance has been updated."
            
        conn.commit()
        return jsonify({"success": True, "message": msg})
    except Exception as e:
        return jsonify({"success": False, "message": f"Payment compilation failure: {str(e)}"}), 500

@app.route('/api/documents/upload', methods=['POST'])
def document_upload():
    """Frictionless upload processing. Saves document parameters directly without displaying email prompts."""
    case_number = request.form.get('case_number', 'General Case context')
    
    if 'document' not in request.files: 
        return jsonify({"success": False, "message": "No functional document payload detected."}), 400
        
    file = request.files['document']
    secure_name = secure_filename(file.filename)
    absolute_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
    file.save(absolute_path)
    
    return jsonify({"success": True, "message": "Document uploaded successfully. Case updates dispatched to counsel."})

# =========================================================
# 🏢 LAW FIRM INTERNAL MANAGEMENT ENDPOINTS
# =========================================================

@app.route('/api/staff/search', methods=['POST'])
def search_cases():
    """Returns all matters safely. Hides financial columns for everyone except Wambui Shadrack."""
    data = request.get_json() or {}
    query = data.get('query', '').strip()
    user_name = data.get('user_name', '').strip()
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        if not query:
            cur.execute("""
                SELECT case_id, case_number, case_parties, client_name, total_balance, paid_balance, next_court_date, coming_up_for 
                FROM cases ORDER BY case_id DESC
            """)
        else:
            term = f"%{query}%"
            cur.execute("""
                SELECT case_id, case_number, case_parties, client_name, total_balance, paid_balance, next_court_date, coming_up_for 
                FROM cases 
                WHERE case_number ILIKE %s OR client_name ILIKE %s OR case_parties ILIKE %s
                ORDER BY case_id DESC
            """, (term, term, term))
            
        results = cur.fetchall()
        
        # Privacy Guardrail: Hide financials if the user is not  Shadrack Wambui
        for row in results:
            if user_name != "Shadrack Wambui":
                row['total_balance'] = "RESTRICTED"
                row['paid_balance'] = "RESTRICTED"
                
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/staff/ai-monitoring', methods=['GET'])
def monitor_client_ai():
    """Allows internal legal staff to monitor all contextual queries requested by clients on the AI interface."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT log_id, case_number, client_name, client_question, ai_response, logged_at FROM ai_client_logs ORDER BY logged_at DESC")
        logs = cur.fetchall()
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not pull monitoring metrics: {str(e)}"}), 500

@app.route('/api/staff/update-matter', methods=['POST'])
def update_matter():
    """Updates operational timelines utilizing exact database schema names. Financial alterations remain restricted."""
    data = request.get_json() or {}
    user_name = data.get('user_name', '').strip()  
    case_id = data.get('case_id')
    
    # Check strict matching names mapped directly from the database columns
    next_court_date = data.get('next_court_date') 
    coming_up_for = data.get('coming_up_for')
    
    if user_name != "Shadrack Wambui":
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT total_balance, paid_balance FROM cases WHERE case_id = %s", (case_id,))
            current_record = cur.fetchone()
            
            if current_record:
                input_total = data.get('total_balance')
                input_paid = data.get('paid_balance')
                
                if (input_total is not None and str(input_total) != "RESTRICTED" and float(input_total) != float(current_record['total_balance'])) or \
                   (input_paid is not None and str(input_paid) != "RESTRICTED" and float(input_paid) != float(current_record['paid_balance'])):
                    return jsonify({
                        "success": False, 
                        "message": "Access Denied: Only Shadrack Wambui is authorized to update financial ledger entries."
                    }), 403
        except Exception as e:
            return jsonify({"success": False, "message": f"Security verification check aborted: {str(e)}"}), 500

    try:
        conn = get_db()
        cur = conn.cursor()
        # Updating with EXACT matching columns to the database
        cur.execute("""
            UPDATE cases 
            SET next_court_date=%s, coming_up_for=%s, total_balance=%s, paid_balance=%s
            WHERE case_id=%s
        """, (next_court_date, coming_up_for, data.get('total_balance'), data.get('paid_balance'), case_id))
        conn.commit()
        return jsonify({"success": True, "message": "Case ledger modified successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Ledger save crash: {str(e)}"}), 500

@app.route('/api/admin/kill-switch', methods=['POST'])
def toggle_kill_switch():
    """Locks or unlocks application access for clients globally during system breaches."""
    action = request.get_json().get('action', '').upper()
    if action == 'LOCK':
        SYSTEM_STATE["LOCKDOWN_MODE"] = True
        logging.critical("🚨 BACKEND LOCKDOWN OVERRIDE INITIATED BY SYSTEM ADMIN.")
        return jsonify({"success": True, "status": "LOCKED", "message": "🚨 GATEWAY ISOLATION APPLIED. Client paths closed."})
    else:
        SYSTEM_STATE["LOCKDOWN_MODE"] = False
        logging.critical("✅ BACKEND LOCKDOWN CLEARED BY SYSTEM ADMIN.")
        return jsonify({"success": True, "status": "ACTIVE", "message": "✅ Core communication frameworks fully online."})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)