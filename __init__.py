from flask import Flask, flash, request, redirect, url_for, render_template, send_file, flash
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
import warnings
warnings.filterwarnings("ignore")

from werkzeug.security import generate_password_hash, check_password_hash

PEOPLE_FOLDER = os.path.join('static','styles')
app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)

# class User(UserMixin, db.Model):
#     id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
#     email = db.Column(db.String(100), unique=True)
#     password = db.Column(db.String(100))
#     name = db.Column(db.String(1000))