from flask import Flask
from app.db import init_db
from app.routes import bp as routes_bp
import logging
from logging.handlers import RotatingFileHandler
import os


def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')
    
    from app.routes import bp as routes_bp
    app.register_blueprint(routes_bp)
    
    return app

def configure_logging(app):
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(app.instance_path, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up file handler
    log_file = os.path.join(log_dir, 'app.log')
    file_handler = RotatingFileHandler(log_file, maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)

    # Set up console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    console_handler.setLevel(logging.INFO)

    # Add handlers to the app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)

    # Add handlers to the root logger as well
    logging.getLogger().addHandler(file_handler)
    logging.getLogger().addHandler(console_handler)
    logging.getLogger().setLevel(logging.INFO)

    app.logger.info('Logging configured')

