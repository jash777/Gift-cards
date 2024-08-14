from flask import Blueprint, jsonify, request, current_app
from app.db import get_db_connection, encrypt_mnemonic, decrypt_mnemonic
from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from hdwallet.utils import generate_mnemonic
import secrets
from mysql.connector import Error
from datetime import datetime
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from dotenv import load_dotenv
import os
import uuid

bp = Blueprint('routes', __name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Secret key for authentication
API_SECRET_KEY = os.environ.get('API_SECRET_KEY') or 'your-secret-key-here'

# Constants
MIN_POOL_SIZE = 100
REPLENISH_SIZE = 500

def authenticate(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        provided_key = request.headers.get('X-API-Key')
        if not provided_key:
            return jsonify({'message': 'API key is missing'}), 401
        if not secrets.compare_digest(provided_key, API_SECRET_KEY):
            return jsonify({'message': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated

def get_hdwallet(mnemonic: str, derivation_path: str) -> BIP44HDWallet:
    hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
    hdwallet.from_mnemonic(mnemonic=mnemonic, language="english")
    hdwallet.from_path(path=derivation_path)
    return hdwallet

def generate_wallet_addresses(mnemonic, count):
    addresses = []
    for _ in range(count):
        derivation_path = f"m/44'/60'/0'/0/{secrets.randbelow(2**32)}"
        hdwallet = get_hdwallet(mnemonic, derivation_path)
        address = hdwallet.address()
        wallet_address_id = str(uuid.uuid4())
        addresses.append((wallet_address_id, address, derivation_path))
    return addresses

def insert_wallet_addresses(cursor, addresses):
    try:
        cursor.executemany('''
            INSERT INTO wallet_addresses 
            (wallet_address_id, address, derivation_path, is_assigned, created_at)
            VALUES (%s, %s, %s, FALSE, NOW())
        ''', addresses)
        return True
    except Error as e:
        logger.error(f"Failed to insert wallet addresses: {str(e)}")
        return False

def get_user_wallet_addresses(cursor, user_id):
    try:
        cursor.execute('''
            SELECT wallet_address_id, address, assigned_at
            FROM wallet_addresses
            WHERE user_id = %s AND is_assigned = TRUE
            ORDER BY assigned_at DESC
        ''', (user_id,))
        return cursor.fetchall()
    except Error as e:
        logger.error(f"Database error in get_user_wallet_addresses: {str(e)}")
        return None

def assign_new_wallet_address(cursor, user_id):
    try:
        cursor.execute('''
            SELECT id, wallet_address_id, address
            FROM wallet_addresses
            WHERE is_assigned = FALSE
            LIMIT 1
            FOR UPDATE
        ''')
        new_address = cursor.fetchone()
        
        if not new_address:
            return None
        
        cursor.execute('''
            UPDATE wallet_addresses
            SET is_assigned = TRUE, assigned_at = NOW(), user_id = %s
            WHERE id = %s
        ''', (user_id, new_address['id']))
        
        new_address['assigned_at'] = datetime.now()
        return new_address
    
    except Error as e:
        logger.error(f"Database error in assign_new_wallet_address: {str(e)}")
        return None

def ensure_wallet_address_pool(conn, cursor, mnemonic):
    cursor.execute('SELECT COUNT(*) as count FROM wallet_addresses WHERE is_assigned = FALSE')
    unassigned_count = cursor.fetchone()['count']
    
    if unassigned_count < MIN_POOL_SIZE:
        addresses_to_generate = REPLENISH_SIZE - unassigned_count
        new_addresses = generate_wallet_addresses(mnemonic, addresses_to_generate)
        if insert_wallet_addresses(cursor, new_addresses):
            conn.commit()
            logger.info(f"Generated and inserted {len(new_addresses)} new wallet addresses")
        else:
            conn.rollback()
            logger.error("Failed to insert new wallet addresses")

def get_mnemonic(cursor):
    cursor.execute('SELECT encrypted_mnemonic, encryption_key FROM mnemonics ORDER BY id DESC LIMIT 1')
    mnemonic_record = cursor.fetchone()
    if not mnemonic_record:
        raise ValueError("No mnemonic found in the database")
    return decrypt_mnemonic(mnemonic_record['encrypted_mnemonic'], mnemonic_record['encryption_key'])

@bp.route('/walletaddress', methods=['POST'])
@authenticate
@limiter.limit("5 per minute")
def assign_wallet_address():
    """Assign a new wallet address to a user or return all addresses for the user."""
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    conn = get_db_connection()
    if not conn:
        logger.error("Database connection failed")
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get all existing wallet addresses for the user
        existing_addresses = get_user_wallet_addresses(cursor, user_id)
        
        # Assign a new wallet address
        new_address = assign_new_wallet_address(cursor, user_id)
        
        if not new_address:
            # Check if we need to generate more addresses
            mnemonic = get_mnemonic(cursor)
            ensure_wallet_address_pool(conn, cursor, mnemonic)
            # Try to assign a new address again
            new_address = assign_new_wallet_address(cursor, user_id)
            
            if not new_address:
                logger.error("No available wallet addresses even after pool replenishment")
                return jsonify({"error": "No available wallet addresses"}), 500

        conn.commit()
        
        # Prepare the response
        response = {
            "user_id": user_id,
            "new_address": {
                "wallet_address_id": new_address['wallet_address_id'],
                "address": new_address['address'],
                "assigned_at": new_address['assigned_at'].isoformat()
            },
            "all_addresses": [
                {
                    "wallet_address_id": addr['wallet_address_id'],
                    "address": addr['address'],
                    "assigned_at": addr['assigned_at'].isoformat()
                } for addr in existing_addresses
            ] if existing_addresses else []
        }
        
        # Add the new address to the list of all addresses
        response["all_addresses"].insert(0, response["new_address"])
        
        return jsonify(response), 200
    except Error as e:
        conn.rollback()
        logger.error(f"Error assigning wallet address: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    except ValueError as e:
        logger.error(f"Value error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

def initialize_wallet_address_pool():
    conn = get_db_connection()
    if not conn:
        logger.error("Database connection failed")
        return

    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get or generate mnemonic
        try:
            mnemonic = get_mnemonic(cursor)
        except ValueError:
            mnemonic = generate_mnemonic(language="english", strength=128)
            encryption_key = secrets.token_bytes(32)
            encrypted_mnemonic = encrypt_mnemonic(mnemonic, encryption_key)
            
            cursor.execute('''
                INSERT INTO mnemonics (encrypted_mnemonic, encryption_key)
                VALUES (%s, %s)
            ''', (encrypted_mnemonic, encryption_key))
            conn.commit()
        
        ensure_wallet_address_pool(conn, cursor, mnemonic)
        
        logger.info("Wallet address pool initialized successfully")
    except Error as e:
        conn.rollback()
        logger.error(f"Error initializing wallet address pool: {e}")
    finally:
        if conn:
            conn.close()

# Call this function when your application starts
initialize_wallet_address_pool()