from flask import Flask, flash, request, redirect, url_for, render_template, send_file, flash
import os
import sys
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
import warnings
warnings.filterwarnings("ignore")

from werkzeug.security import generate_password_hash, check_password_hash
from __init__ import app, db
from models import User

PEOPLE_FOLDER = os.path.join('static','styles')
# app = Flask(__name__)

# app.config['SECRET_KEY'] = 'secret-key-goes-here'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
# db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# class User(UserMixin, db.Model):
#     id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
#     email = db.Column(db.String(100), unique=True)
#     password = db.Column(db.String(100))
#     name = db.Column(db.String(1000))

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))

@app.route("/")
def index():
    if(sys.argv[1] == '--admin'):
        print("Opening Niffler in Admin mode !!")
    return render_template('index.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return render_template('login.html') # if the user doesn't exist or password is wrong, reload the page

        # if the above check passes, then we know the user has the right credentials
        login_user(user, remember=remember)
        return render_template('profile.html', name=current_user.name)
    return render_template('login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method =='POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

        if user: # if a user is found, we want to redirect back to signup page so user can try again
            flash('Email address already exists')
            return render_template('signup.html')

        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        return render_template('login.html')

    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('index.html')
#JUST DO IT!!!
if __name__=="__main__":
    app.run(port="9000")
