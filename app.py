from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv
from argon2 import PasswordHasher
import bleach
import os
import requests
import base64
import uuid
from datetime import datetime
from sqlalchemy import text

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

db = SQLAlchemy(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day"])
CORS(app, supports_credentials=True, origins=[os.getenv('FRONTEND_URL', '*')])
ph = PasswordHasher()

MOMO_CLIENT_ID = os.getenv('MOMO_CLIENT_ID')
MOMO_CLIENT_SECRET = os.getenv('MOMO_CLIENT_SECRET')
MOMO_API_KEY = os.getenv('MOMO_API_KEY')
MOMO_BASE_URL = os.getenv('MOMO_BASE_URL', 'https://sandbox.momodeveloper.mtn.com')
MOMO_TARGET_ENV = os.getenv('MOMO_TARGET_ENV', 'sandbox')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    image_url = db.Column(db.Text)  # Handles large Base64 strings
    is_active = db.Column(db.Boolean, default=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    payment_method = db.Column(db.String(20), default='cash')
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), default='pending')
    momo_ref = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.Column(db.JSON)

def get_momo_token():
    try:
        cred = f"{MOMO_CLIENT_ID}:{MOMO_CLIENT_SECRET}"
        encoded = base64.b64encode(cred.encode('utf-8')).decode('utf-8')
        headers = {
            'Authorization': f'Basic {encoded}',
            'Ocp-Apim-Subscription-Key': MOMO_API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        resp = requests.post(f"{MOMO_BASE_URL}/collection/token/", headers=headers)
        resp.raise_for_status()
        return resp.json().get('access_token')
    except Exception as e:
        print(f"Token Error: {e}")
        return None

def initiate_momo_payment(amount, phone, external_id):
    phone = phone.strip()
    if phone.startswith('0'): phone = '256' + phone[1:]
    elif not phone.startswith('256'): phone = '256' + phone

    token = get_momo_token()
    if not token: return {"error": "Failed to get MTN token"}

    headers = {
        'Authorization': f'Bearer {token}',
        'X-Target-Environment': MOMO_TARGET_ENV,
        'Ocp-Apim-Subscription-Key': MOMO_API_KEY,
        'Content-Type': 'application/json',
        'Idempotency-Key': str(uuid.uuid4())
    }
    payload = {        "amount": str(amount), "currency": "UGX", "externalId": str(external_id),
        "payer": {"partyIdType": "MSISDN", "partyId": phone},
        "payerMessage": "The Subject Shop", "payeeNote": "Thank you!"
    }
    try:
        resp = requests.post(f"{MOMO_BASE_URL}/collection/v1_0/requesttopay", json=payload, headers=headers)
        if resp.status_code == 202:
            return {"status": "initiated", "reference": resp.headers.get('X-Reference-Id')}
        else:
            print(f"MTN API Error: {resp.status_code} - {resp.text}")
            if MOMO_TARGET_ENV == 'sandbox':
                return {"status": "initiated", "reference": f"sandbox-ref-{uuid.uuid4()}"}
            return {"error": resp.text}
    except Exception as e:
        print(f"MTN Exception: {e}")
        return {"error": str(e)}

def check_payment_status(reference):
    try:
        token = get_momo_token()
        if not token: return "error"
        headers = {
            'Authorization': f'Bearer {token}',
            'X-Target-Environment': MOMO_TARGET_ENV,
            'Ocp-Apim-Subscription-Key': MOMO_API_KEY
        }
        resp = requests.get(f"{MOMO_BASE_URL}/collection/v1_0/requesttopay/{reference}", headers=headers)
        return resp.json().get('financialTransactionStatus', 'UNKNOWN')
    except Exception as e:
        print(f"Status check error: {e}")
        return "error"

# --- DB INIT & AUTO-MIGRATION ---
with app.app_context():
    db.create_all()
    # Auto-fix column type on existing databases (runs safely on every startup)
    try:
        result = db.session.execute(text("""
            SELECT data_type FROM information_schema.columns
            WHERE table_name = 'product' AND column_name = 'image_url';
        """))
        if result.scalar() != 'text':
            db.session.execute(text("ALTER TABLE product ALTER COLUMN image_url TYPE TEXT;"))
            db.session.commit()
            print("✅ Database migration: image_url column updated to TEXT")
    except Exception as e:
        print(f"Migration note: {e}")

    # Admin password sync
    admin = User.query.filter_by(is_admin=True).first()
    if admin:
        admin.password_hash = ph.hash(os.getenv('ADMIN_PASSWORD', 'Pass123'))
        db.session.commit()
    else:
        admin = User(
            username='Admin',
            email=os.getenv(),
            password_hash=ph.hash(os.getenv()),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# --- API ROUTES ---
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    try:
        data = request.get_json()
        email = bleach.clean(data.get('email', ''))
        pwd = data.get('password', '')
        username = bleach.clean(data.get('username', ''))
        if not email or not pwd or not username: return jsonify({"error": "All fields required"}), 400
        if User.query.filter_by(email=email).first(): return jsonify({"error": "Email already exists"}), 400
        user = User(username=username, email=email, password_hash=ph.hash(pwd))
        db.session.add(user); db.session.commit()
        return jsonify({"message": "Registration successful"}), 201
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        email = bleach.clean(data.get('email', ''))
        pwd = data.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and ph.verify(user.password_hash, pwd):
            session['user_id'] = user.id; session['is_admin'] = user.is_admin
            return jsonify({"message": "Login successful", "isAdmin": user.is_admin})
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"})

@app.route('/api/products', methods=['GET'])
def get_products():    
    try:
        products = Product.query.filter_by(is_active=True).all()
        return jsonify([{"id": p.id, "name": p.name, "category": p.category, "price": p.price, "stock": p.stock, "image": p.image_url} for p in products])
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/admin/product', methods=['POST'])
@limiter.limit("20 per hour")
def create_product():
    if not session.get('is_admin'): return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json()
        product = Product(
            name=bleach.clean(data.get('name', '')), category=data.get('category', 'General'),
            price=float(data.get('price', 0)), stock=int(data.get('stock', 0)), image_url=data.get('image', '')
        )
        db.session.add(product); db.session.commit()
        return jsonify({"message": "Product created", "id": product.id}), 201
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/order', methods=['POST'])
@limiter.limit("10 per hour")
def place_order():
    try:
        data = request.get_json()
        cart = data.get('cart', []); total = float(data.get('total', 0)); method = data.get('method', 'cash')
        if not cart: return jsonify({"error": "Cart is empty"}), 400
        order = Order(full_name=bleach.clean(data.get('fullName', '')), phone=bleach.clean(data.get('phone', '')),
                      address=bleach.clean(data.get('address', '')), payment_method=method, total_amount=total,
                      items=cart, status='pending')
        db.session.add(order); db.session.flush()
        if method in ['mtn', 'airtel']:
            payment_result = initiate_momo_payment(total, data.get('phone'), str(order.id))
            if 'error' in payment_result:
                db.session.rollback(); return jsonify({"error": "Payment initiation failed"}), 500
            order.momo_ref = payment_result['reference']; order.status = 'payment_initiated'
            db.session.commit()
            return jsonify({"status": "initiated", "reference": payment_result['reference'], "orderId": order.id})
        else:
            order.status = 'pending_cash'; db.session.commit()
            return jsonify({"status": "pending", "orderId": order.id})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/order/status/<int:order_id>', methods=['GET'])
def check_order_status(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        if order.status == 'payment_initiated' and order.momo_ref:
            status = check_payment_status(order.momo_ref)
            if status == 'SUCCESSFUL':
                for item in order.items:
                    product = Product.query.get(item.get('id'))
                    if product and product.stock >= item.get('quantity', 1): 
                        product.stock -= item.get('quantity', 1)
                order.status = 'paid'; db.session.commit()
                return jsonify({"status": "paid"})
            elif status in ['FAILED', 'REJECTED']:
                order.status = 'failed'; db.session.commit()
                return jsonify({"status": "failed"})
        return jsonify({"status": order.status})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/admin/orders', methods=['GET'])
def get_admin_orders():
    if not session.get('is_admin'): return jsonify({"error": "Unauthorized"}), 403
    try:
        orders = Order.query.order_by(Order.created_at.desc()).limit(50).all()
        return jsonify([{"id": o.id, "fullName": o.full_name, "phone": o.phone, "total": o.total_amount,
                         "status": o.status, "paymentMethod": o.payment_method, "createdAt": o.created_at.isoformat()} for o in orders])
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/admin/product/<int:product_id>/stock', methods=['PATCH'])
def update_product_stock(product_id):
    if not session.get('is_admin'): return jsonify({"error": "Unauthorized"}), 403
    try:
        delta = int(request.get_json().get('delta', 0))
        product = Product.query.get_or_404(product_id)
        product.stock = max(0, product.stock + delta); db.session.commit()
        return jsonify({"status": "updated", "stock": product.stock})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/admin/product/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    if not session.get('is_admin'): return jsonify({"error": "Unauthorized"}), 403
    try:
        product = Product.query.get_or_404(product_id)
        product.is_active = False; db.session.commit()
        return jsonify({"message": "Product deleted"})
    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
