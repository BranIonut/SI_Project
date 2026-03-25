from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kms_local.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Framework(db.Model):
    __tablename__ = 'frameworks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    version = db.Column(db.String(20))


class Algorithm(db.Model):
    __tablename__ = 'algorithms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    type=db.Column(db.String(20), nullable=False)


class Key(db.Model):
    __tablename__ = 'keys'
    id = db.Column(db.Integer, primary_key=True)
    algorithm_id = db.Column(db.Integer, db.ForeignKey('algorithms.id'), nullable=False)
    key_value = db.Column(db.LargeBinary, nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)

    algoritm = db.relationship('Algorithm', backref='keys')


class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    enc_file_path = db.Column(db.String(255))
    state = db.Column(db.String(20), default='Unencrypted')


class Performance(db.Model):
    __tablename__ = 'performances'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'))
    algorithm_id = db.Column(db.Integer, db.ForeignKey('algorithms.id'))
    framework_id = db.Column(db.Integer, db.ForeignKey('frameworks.id'))

    operation = db.Column(db.String(20))
    exec_time_ms = db.Column(db.Float, nullable=False)
    used_mem_kb = db.Column(db.Float, nullable=False)


with app.app_context():
    db.create_all()
    print("Database and tables created successfully!")