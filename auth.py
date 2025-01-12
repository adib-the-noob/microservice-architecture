from app import bcrypt
from flask_bcrypt import Bcrypt

def hash_password(password: str):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password(password: str, hashed_password: str):
    return bcrypt.check_password_hash(hashed_password, password)