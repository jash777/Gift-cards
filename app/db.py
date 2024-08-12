# from flask import current_app
# import mysql.connector
# from mysql.connector import Error

# def get_db_connection():
#     try:
#         conn = mysql.connector.connect(**current_app.config['DB_CONFIG'])
#         return conn
#     except Error as e:
#         current_app.logger.error(f"Error connecting to MySQL: {e}")
#         return None

# def init_db():
#     conn = get_db_connection()
#     if conn:
#         try:
#             cursor = conn.cursor()
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS wallet_addresses (
#                     id INT AUTO_INCREMENT PRIMARY KEY,
#                     address VARCHAR(42) UNIQUE NOT NULL,
#                     name VARCHAR(255),
#                     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
#                     last_used DATETIME,
#                     derivation_path VARCHAR(50) UNIQUE NOT NULL
#                 )
#             ''')
#             conn.commit()
#         except Error as e:
#             current_app.logger.error(f"Error creating table: {e}")
#         finally:
#             conn.close()

from cryptography.fernet import Fernet
import mysql.connector
from mysql.connector import Error
from flask import current_app
import os
import logging


logging.basicConfig(level=logging.INFO)


def generate_key():
    """Generate and return a new key for encryption."""
    return Fernet.generate_key().decode()


def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        return connection
    except Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        return None

def encrypt_mnemonic(mnemonic: str, key: bytes) -> bytes:
    """Encrypt the mnemonic using the provided key."""
    try:
        fernet = Fernet(key)
        encrypted_mnemonic = fernet.encrypt(mnemonic.encode())
        logging.info("Mnemonic encrypted successfully")
        return encrypted_mnemonic
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_mnemonic(encrypted_mnemonic: bytes, key: bytes) -> str:
    """Decrypt the mnemonic using the provided key."""
    try:
        fernet = Fernet(key)
        decrypted_mnemonic = fernet.decrypt(encrypted_mnemonic).decode()
        logging.info("Mnemonic decrypted successfully")
        return decrypted_mnemonic
    except InvalidToken:
        logging.error("Invalid decryption key provided")
        raise ValueError("Invalid decryption key")
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        raise

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def init_db():
    """Initialize the database."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS wallet_addresses (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    address VARCHAR(42) UNIQUE NOT NULL,
                    name VARCHAR(255),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_used DATETIME,
                    derivation_path VARCHAR(50) UNIQUE NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mnemonics (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    encrypted_mnemonic TEXT NOT NULL,
                    encryption_key VARCHAR(44) NOT NULL
                )
            ''')
            conn.commit()
        except Error as e:
            current_app.logger.error(f"Error creating tables: {e}")
        finally:
            conn.close()
