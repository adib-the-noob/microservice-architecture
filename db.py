import os
from flask_sqlalchemy import SQLAlchemy
from app import server

# db config
server.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:hacker@localhost/microservicedb'
server.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(server)