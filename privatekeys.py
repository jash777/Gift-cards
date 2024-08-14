import os
import sys
import logging
import mysql.connector
from mysql.connector import Error
from cryptography.fernet import Fernet
from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

# Encryption key for the master key (should be stored securely, not in the code or env file)
MASTER_KEY = os.getenv('MASTER_ENCRYPTION_KEY')

def decrypt_mnemonic(encrypted_mnemonic, encryption_key):
    f = Fernet(encryption_key)
    return f.decrypt(encrypted_mnemonic.encode()).decode()

def get_hdwallet(mnemonic: str, derivation_path: str) -> BIP44HDWallet:
    hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
    hdwallet.from_mnemonic(mnemonic=mnemonic, language="english")
    hdwallet.from_path(path=derivation_path)
    return hdwallet

def get_mnemonic(cursor):
    cursor.execute('SELECT encrypted_mnemonic, encryption_key FROM mnemonics ORDER BY id DESC LIMIT 1')
    mnemonic_record = cursor.fetchone()
    if not mnemonic_record:
        raise ValueError("No mnemonic found in the database")
    return decrypt_mnemonic(mnemonic_record['encrypted_mnemonic'], mnemonic_record['encryption_key'])

def get_user_wallet_addresses(cursor, user_id):
    cursor.execute('''
        SELECT wallet_address_id, address, derivation_path
        FROM wallet_addresses
        WHERE user_id = %s AND is_assigned = TRUE
    ''', (user_id,))
    return cursor.fetchall()

def retrieve_private_keys(user_id):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Retrieve mnemonic
        mnemonic = get_mnemonic(cursor)

        # Get user's wallet addresses
        addresses = get_user_wallet_addresses(cursor, user_id)

        private_keys = {}
        for addr in addresses:
            hdwallet = get_hdwallet(mnemonic, addr['derivation_path'])
            private_key = hdwallet.private_key()
            private_keys[addr['address']] = private_key

        return private_keys

    except Error as e:
        logger.error(f"Database error: {e}")
        return None
    except Exception as e:
        logger.error(f"Error retrieving private keys: {e}")
        return None
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python private_key_retrieval.py <user_id>")
        sys.exit(1)

    user_id = sys.argv[1]

    # Here you would implement additional security checks
    # For example, verifying the identity of the person running the script
    # and logging the access attempt

    private_keys = retrieve_private_keys(user_id)

    if private_keys:
        for address, key in private_keys.items():
            print(f"Address: {address}")
            print(f"Private Key: {key}")
            print("--------------------")
    else:
        print("Failed to retrieve private keys.")

if __name__ == "__main__":
    main()