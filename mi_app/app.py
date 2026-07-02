import os
import sqlite3
import secrets
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURACIÓN DE BASE DE DATOS ---
DB_NAME = "bank_secure.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Tabla de Usuarios (Cuentas)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        phone TEXT,
        email TEXT,
        balance REAL
    )''')
    
    # Tabla de Operaciones (Transacciones)
    c.execute('''CREATE TABLE IF NOT EXISTS operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        amount REAL,
        timestamp TEXT,
        status TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Insertar usuario ficticio si no existe
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password_hash, phone, email, balance) VALUES (?, ?, ?, ?, ?)",
                  ('admin', generate_password_hash('1234'), '+521234567890', 'admin@correo.com', 5000.00))
    
    conn.commit()
    conn.close()

# --- HELPERS ---
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Almacenamiento en memoria para códigos 2FA temporales (En producción usar Redis)
otp_temp_store = {}

# --- RUTAS DE VISTAS ---
@app.route('/')
def index():
    return render_template('index.html')

# --- API ENDPOINTS ---

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        # Generar 2FA (Simulado)
        otp_code = secrets.randbelow(900000) + 100000
        otp_temp_store[user['id']] = str(otp_code)
        
        # Simular envío de SMS/Correo (Lo devolvemos en la respuesta para el frontend)
        mock_message = f"SMS/Correo enviado a {user['phone']} / {user['email']}. Tu código es: {otp_code}"
        
        return jsonify({
            "status": "2FA_REQUIRED", 
            "user_id": user['id'],
            "mock_message": mock_message # En producción, esto NO se envía al cliente
        })
    return jsonify({"status": "ERROR", "message": "Credenciales inválidas"}), 401

@app.route('/api/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    user_id = data.get('user_id')
    otp = data.get('otp')
    
    if otp_temp_store.get(user_id) == otp:
        del otp_temp_store[user_id] # Usar y borrar
        return jsonify({"status": "BIOMETRIC_REQUIRED", "message": "2FA Exitoso. Procede a biometría."})
    return jsonify({"status": "ERROR", "message": "Código 2FA incorrecto"}), 400

@app.route('/api/verify_biometric', methods=['POST'])
def verify_biometric():
    data = request.json
    user_id = data.get('user_id')
    
    # En un entorno real, aquí se validaría el token de WebAuthn o similar.
    # Para fines de simulación, aceptamos la validación del frontend.
    if user_id:
        return jsonify({"status": "SUCCESS", "message": "Biometría validada. Acceso concedido."})
    return jsonify({"status": "ERROR", "message": "Fallo biométrico"}), 400

@app.route('/api/dashboard/<int:user_id>', methods=['GET'])
def dashboard(user_id):
    conn = get_db()
    user = conn.execute("SELECT username, balance FROM users WHERE id=?", (user_id,)).fetchone()
    ops = conn.execute("SELECT * FROM operations WHERE user_id=? ORDER BY timestamp DESC LIMIT 5", (user_id,)).fetchall()
    conn.close()
    
    return jsonify({
        "username": user['username'],
        "balance": user['balance'],
        "history": [dict(op) for op in ops]
    })

@app.route('/api/operate', methods=['POST'])
def operate():
    data = request.json
    user_id = data.get('user_id')
    amount = float(data.get('amount'))
    op_type = data.get('type') # 'deposit' o 'withdraw'
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    
    if not user:
        return jsonify({"status": "ERROR", "message": "Usuario no encontrado"}), 404
        
    new_balance = user['balance']
    if op_type == 'withdraw':
        if amount > user['balance']:
            return jsonify({"status": "ERROR", "message": "Fondos insuficientes"}), 400
        new_balance -= amount
    elif op_type == 'deposit':
        new_balance += amount
        
    conn.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
    conn.execute("INSERT INTO operations (user_id, type, amount, timestamp, status) VALUES (?, ?, ?, ?, ?)",
                 (user_id, op_type, amount, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "COMPLETED"))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "SUCCESS", "new_balance": new_balance})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)