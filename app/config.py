import os
from dotenv import load_dotenv
from hdwallet.utils import generate_mnemonic  # Make sure this line is present

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
    DB_CONFIG = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'user': os.getenv('DB_USER'),
        'password': os.getenv('DB_PASSWORD'),
        'database': os.getenv('DB_NAME')
    }
    
    MNEMONIC = os.getenv("MNEMONIC") or generate_mnemonic(language="english", strength=128)
