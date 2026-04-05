from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

# database.py
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    mfa_secret = db.Column(db.String(32))
    # ADD THIS LINE:
    security_keyword = db.Column(db.String(100), nullable=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150))
    access_level = db.Column(db.String(50)) 
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'))