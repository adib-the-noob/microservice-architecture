from flask import Flask
from flask import request, jsonify, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

import jwt
import datetime
from datetime import datetime, timedelta


from models import User
from db import db

server = Flask(__name__)
server.config['SECRET_KEY'] = 'secretkey'

# db config
server.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:hacker@localhost/microservicedb'
server.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(server)
bcrypt = Bcrypt(server)

@server.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # save to db
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'message': 'User created successfully',
        'username': new_user.username,
        'hashed_password': new_user.password
    })


@server.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data["username"] or not data["password"]:
        return jsonify({
            'message': 'Could not verify',
            'WWW-Authenticate': 'Basic auth="Login required"'
        }, 401)

    user = User.query.filter_by(username=data["username"]).first()
    
    if not user:
        return jsonify({
            'message': 'Could not verify',
            'WWW-Authenticate': 'Basic auth="Login required"'
        }, 401)
    
    if bcrypt.check_password_hash(user.password, data["password"]):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, server.config['SECRET_KEY'])
        return jsonify({
            'message': 'Login successful',
            'token': token
        })
    

if __name__ == '__main__':
    with server.app_context():
        db.create_all()
    server.run(debug=True, port=8000)