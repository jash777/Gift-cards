from flask import Blueprint, jsonify, request, current_app
from app.db import get_db_connection, encrypt_mnemonic, decrypt_mnemonic
from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from hdwallet.utils import generate_mnemonic
import secrets
from mysql.connector import Error
from datetime import datetime, timedelta
from functools import wraps
import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from dotenv import load_dotenv
import os

bp = Blueprint('routes', __name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Secret key for JWT
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'default-secret-key'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated

def get_hdwallet(mnemonic: str, derivation_path: str) -> BIP44HDWallet:
    hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
    hdwallet.from_mnemonic(mnemonic=mnemonic, language="english")
    hdwallet.from_path(path=derivation_path)
    return hdwallet

def generate_unique_derivation_path(cursor):
    max_attempts = 10
    for attempt in range(max_attempts):
        cursor.execute("SELECT MAX(CAST(SUBSTRING_INDEX(derivation_path, '/', -1) AS UNSIGNED)) as max_index FROM wallet_addresses")
        result = cursor.fetchone()
        index = (result['max_index'] or -1) + 1 + attempt
        derivation_path = f"m/44'/60'/0'/0/{index}"
        
        cursor.execute("SELECT COUNT(*) as count FROM wallet_addresses WHERE derivation_path = %s", (derivation_path,))
        if cursor.fetchone()['count'] == 0:
            return derivation_path
    
    logger.error(f"Failed to generate a unique derivation path after {max_attempts} attempts")
    raise ValueError("Failed to generate a unique derivation path")

def insert_wallet_address(cursor, address, name, derivation_path):
    try:
        cursor.execute('''
            INSERT INTO wallet_addresses (address, name, derivation_path)
            VALUES (%s, %s, %s)
        ''', (address, name, derivation_path))
        return True
    except Error as e:
        logger.error(f"Failed to insert new wallet address: {str(e)}")
        return False

@bp.route('/walletaddress', methods=['POST'])
# @token_required
# @limiter.limit("5 per minute")
def assign_wallet_address():
    """Assign a new wallet address based on the stored mnemonic."""
    conn = get_db_connection()
    if not conn:
        logger.error("Database connection failed")
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get the latest mnemonic
        cursor.execute('SELECT encrypted_mnemonic, encryption_key FROM mnemonics ORDER BY id DESC LIMIT 1')
        mnemonic_record = cursor.fetchone()
        if not mnemonic_record:
            logger.error("Mnemonic not found. Attempting to generate a new one.")
            result = generate_and_store_mnemonic()
            if isinstance(result, tuple) and result[1] != 200:
                return result
            
            cursor.execute('SELECT encrypted_mnemonic, encryption_key FROM mnemonics ORDER BY id DESC LIMIT 1')
            mnemonic_record = cursor.fetchone()
            if not mnemonic_record:
                logger.error("Failed to generate and retrieve new mnemonic")
                return jsonify({"error": "Failed to generate and retrieve new mnemonic"}), 500

        logger.info("Mnemonic record retrieved")
        
        try:
            decrypted_mnemonic = decrypt_mnemonic(mnemonic_record['encrypted_mnemonic'], mnemonic_record['encryption_key'])
        except Exception as e:
            logger.error(f"Failed to decrypt mnemonic: {str(e)}")
            return jsonify({"error": "Failed to decrypt mnemonic"}), 500

        logger.info("Mnemonic decrypted successfully")
        
        try:
            derivation_path = generate_unique_derivation_path(cursor)
        except ValueError as e:
            return jsonify({"error": str(e)}), 500

        logger.info(f"Generated unique derivation path: {derivation_path}")
        
        # Get the wallet for this derivation path
        try:
            hdwallet = get_hdwallet(decrypted_mnemonic, derivation_path)
            address = hdwallet.address()
        except Exception as e:
            logger.error(f"Failed to generate wallet address: {str(e)}")
            return jsonify({"error": "Failed to generate wallet address"}), 500

        logger.info(f"Wallet address generated: {address}")
        
        # Generate a unique name for the address
        name = f"GiftCard-{secrets.token_hex(4)}"
        
        # Insert new address into database
        if not insert_wallet_address(cursor, address, name, derivation_path):
            conn.rollback()
            return jsonify({"error": "Failed to insert new wallet address"}), 500

        conn.commit()

        # Fetch the inserted record
        cursor.execute('SELECT * FROM wallet_addresses WHERE address = %s', (address,))
        wallet_info = cursor.fetchone()
        
        logger.info(f"New wallet address assigned: {address}")
        
        return jsonify({
            "id": wallet_info['id'],
            "address": wallet_info['address'],
            "name": wallet_info['name'],
            "created_at": wallet_info['created_at'].isoformat()
        }), 200
    except Error as e:
        conn.rollback()
        logger.error(f"Error assigning wallet address: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

# @bp.route('/login', methods=['POST'])
# def login():

#     username = request.json.get('username', None)
#     password = request.json.get('password', None)
#     if username == 'admin' and password == 'password':
#         token = jwt.encode({
#             'user': username,
#             'exp': datetime.utcnow() + timedelta(hours=24)
#         }, JWT_SECRET_KEY)
#         return jsonify({'token': token})
    
#     return jsonify({'message': 'Invalid credentials'}), 401

# Add this function to generate and store a new mnemonic
def generate_and_store_mnemonic():
    mnemonic = generate_mnemonic(language="english", strength=128)
    encryption_key = secrets.token_bytes(32)  # Generate a new encryption key
    encrypted_mnemonic = encrypt_mnemonic(mnemonic, encryption_key)
    
    conn = get_db_connection()
    if not conn:
        logger.error("Database connection failed")
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO mnemonics (encrypted_mnemonic, encryption_key)
            VALUES (%s, %s)
        ''', (encrypted_mnemonic, encryption_key))
        conn.commit()
        logger.info("New mnemonic generated and stored successfully")
        return jsonify({"message": "New mnemonic generated and stored successfully"}), 200
    except Error as e:
        conn.rollback()
        logger.error(f"Error storing new mnemonic: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()