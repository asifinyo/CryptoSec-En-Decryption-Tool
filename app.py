from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import base64
import logging
import uuid

app = Flask(__name__, static_folder='static', static_url_path='/')
CORS(app)

# Loglama quraşdırması
logging.basicConfig(filename='crypto_errors.log', level=logging.ERROR, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Sadə token saxlama
valid_tokens = set()

# Token yoxlaması
def check_auth():
    token = request.headers.get('Authorization')
    if not token or token not in valid_tokens:
        return False
    return True

# Statik faylları xidmət et
@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/login.html')
def serve_login():
    return send_from_directory(app.static_folder, 'login.html')

# Simmetrik şifrələmə (AES, ChaCha20, TripleDES)
def encrypt_symmetric(content, algorithm, key):
    try:
        if algorithm == 'aes':
            key = key.encode().ljust(32)[:32]  # 256-bit
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padded_content = content.encode() + b" " * (16 - len(content.encode()) % 16)
            encrypted = encryptor.update(padded_content) + encryptor.finalize()
            return {"iv": base64.b64encode(iv).decode(), "ciphertext": base64.b64encode(encrypted).decode()}
        elif algorithm == 'chacha20':
            key = key.encode().ljust(32)[:32]  # 256-bit
            nonce = os.urandom(16)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(content.encode()) + encryptor.finalize()
            return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(encrypted).decode()}
        elif algorithm == 'tripledes':
            key = key.encode().ljust(24)[:24]  # 192-bit
            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padded_content = content.encode() + b" " * (8 - len(content.encode()) % 8)
            encrypted = encryptor.update(padded_content) + encryptor.finalize()
            return {"iv": base64.b64encode(iv).decode(), "ciphertext": base64.b64encode(encrypted).decode()}
        else:
            raise Exception("Dəstəklənməyən alqoritm")
    except Exception as e:
        logging.error(f"Simmetrik şifrələmə xətası (alqoritm: {algorithm}): {str(e)}")
        raise Exception("Şifrələmə xətası")

def decrypt_symmetric(data, algorithm, key):
    try:
        if algorithm == 'aes':
            key = key.encode().ljust(32)[:32]
            iv = base64.b64decode(data["iv"])
            ciphertext = base64.b64decode(data["ciphertext"])
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted.rstrip(b" ").decode()
        elif algorithm == 'chacha20':
            key = key.encode().ljust(32)[:32]
            nonce = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["ciphertext"])
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted.decode()
        elif algorithm == 'tripledes':
            key = key.encode().ljust(24)[:24]
            iv = base64.b64decode(data["iv"])
            ciphertext = base64.b64decode(data["ciphertext"])
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted.rstrip(b" ").decode()
        else:
            raise Exception("Dəstəklənməyən alqoritm")
    except Exception as e:
        logging.error(f"Simmetrik deşifrələmə xətası (alqoritm: {algorithm}): {str(e)}")
        raise Exception("Deşifrələmə xətası")

# Asimmetrik şifrələmə (RSA, ECC)
def generate_rsa_keys():
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKey
        ).decode()
        return private_pem, public_pem
    except Exception as e:
        logging.error(f"RSA açar generasiya xətası: {str(e)}")
        raise Exception("Açar generasiya xətası")

def generate_ecc_keys():
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKey
        ).decode()
        return private_pem, public_pem
    except Exception as e:
        logging.error(f"ECC açar generasiya xətası: {str(e)}")
        raise Exception("Açar generasiya xətası")

def encrypt_asymmetric(content, public_pem, algorithm):
    try:
        public_key = serialization.load_pem_public_key(public_pem.encode())
        if algorithm == 'rsa':
            encrypted = public_key.encrypt(
                content.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            return base64.b64encode(encrypted).decode()
        elif algorithm == 'ecc':
            # ECC ilə birbaşa şifrələmə əvəzinə ECDH istifadə edirik
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = serialization.load_pem_public_key(public_pem.encode())
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            # Simmetrik açar yaratmaq üçün HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
            # AES ilə şifrələmə
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padded_content = content.encode() + b" " * (16 - len(content.encode()) % 16)
            encrypted = encryptor.update(padded_content) + encryptor.finalize()
            # Privat açarı da qaytarırıq ki, deşifrələmə mümkün olsun
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            return {
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(encrypted).decode(),
                "ephemeral_private_key": private_pem
            }
        else:
            raise Exception("Dəstəklənməyən alqoritm")
    except Exception as e:
        logging.error(f"Asimmetrik şifrələmə xətası (alqoritm: {algorithm}): {str(e)}")
        raise Exception("Şifrələmə xətası")

def decrypt_asymmetric(encrypted_content, private_pem, algorithm):
    try:
        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        if algorithm == 'rsa':
            decrypted = private_key.decrypt(
                base64.b64decode(encrypted_content),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            return decrypted.decode()
        elif algorithm == 'ecc':
            # ECC deşifrələməsi üçün müştərinin public açarı və serverin ephemeral private açarı istifadə olunur
            private_key = serialization.load_pem_private_key(encrypted_content["ephemeral_private_key"].encode(), password=None)
            public_key = serialization.load_pem_public_key(private_pem.encode())
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
            iv = base64.b64decode(encrypted_content["iv"])
            ciphertext = base64.b64decode(encrypted_content["ciphertext"])
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted.rstrip(b" ").decode()
        else:
            raise Exception("Dəstəklənməyən alqoritm")
    except Exception as e:
        logging.error(f"Asimmetrik deşifrələmə xətası (alqoritm: {algorithm}): {str(e)}")
        raise Exception("Deşifrələmə xətası")

# Login endpoint-i
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        if username == 'admin' and password == 'password':
            token = str(uuid.uuid4())
            valid_tokens.add(token)
            return jsonify({"status": "success", "token": token})
        else:
            return jsonify({"status": "error", "message": "Yanlış istifadəçi adı və ya şifrə"}), 401
    except Exception as e:
        logging.error(f"Login xətası: {str(e)}")
        return jsonify({"status": "error", "message": "Login xətası"}), 500

@app.route('/generate_rsa_key', methods=['POST'])
def generate_rsa_key():
    if not check_auth():
        return jsonify({"status": "error", "message": "Giriş tələb olunur"}), 401
    try:
        private_pem, public_pem = generate_rsa_keys()
        return jsonify({"status": "success", "public_key": public_pem, "private_key": private_pem})
    except Exception as e:
        return jsonify({"status": "error", "message": "Açar generasiya xətası"})

@app.route('/generate_ecc_key', methods=['POST'])
def generate_ecc_key():
    if not check_auth():
        return jsonify({"status": "error", "message": "Giriş tələb olunur"}), 401
    try:
        private_pem, public_pem = generate_ecc_keys()
        return jsonify({"status": "success", "public_key": public_pem, "private_key": private_pem})
    except Exception as e:
        return jsonify({"status": "error", "message": "Açar generasiya xətası"})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if not check_auth():
        return jsonify({"status": "error", "message": "Giriş tələb olunur"}), 401
    try:
        data = request.json
        content = data["content"]
        algorithm = data["algorithm"].lower()
        key = data.get("key", "secret")

        if algorithm in ['aes', 'chacha20', 'tripledes']:
            result = encrypt_symmetric(content, algorithm, key)
            return jsonify({"status": "success", "encrypted": result})
        elif algorithm in ['rsa', 'ecc']:
            private_pem, public_pem = generate_rsa_keys() if algorithm == 'rsa' else generate_ecc_keys()
            encrypted = encrypt_asymmetric(content, public_pem, algorithm)
            return jsonify({"status": "success", "encrypted": encrypted, "private_key": private_pem})
        else:
            return jsonify({"status": "error", "message": "Dəstəklənməyən alqoritm"})
    except Exception as e:
        return jsonify({"status": "error", "message": "Şifrələmə xətası"})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if not check_auth():
        return jsonify({"status": "error", "message": "Giriş tələb olunur"}), 401
    try:
        data = request.json
        content = data["content"]
        algorithm = data["algorithm"].lower()
        key = data.get("key", "secret")

        if algorithm in ['aes', 'chacha20', 'tripledes']:
            result = decrypt_symmetric(content, algorithm, key)
            return jsonify({"status": "success", "decrypted": result})
        elif algorithm in ['rsa', 'ecc']:
            decrypted = decrypt_asymmetric(content, key, algorithm)
            return jsonify({"status": "success", "decrypted": decrypted})
        else:
            return jsonify({"status": "error", "message": "Dəstəklənməyən alqoritm"})
    except Exception as e:
        return jsonify({"status": "error", "message": "Deşifrələmə xətası"})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))