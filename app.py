from config import Config
from datetime import datetime
from flask import Flask, session, redirect, render_template, request, flash, url_for
from flask_mail import Mail, Message
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
import email_validator
import os
import re
import secrets

app = Flask(__name__)
app.config.from_object(Config)

app.secret_key = os.environ.get('Tasky_secret_key')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db' # Database for app data (default db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.config['MAIL_SERVER'] = 'smtp.gmail.com'

db = SQLAlchemy(app)
mail = Mail(app)

# Configure Flask-Session to use SQLAlchemy for session storage
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'

# Initialize Flask-Session
Session(app)

# Tables
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime)

class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_name = db.Column(db.String(100), nullable=False)
    user = db.relationship('User', backref='tasks')  # Establish a relationship with the User table

class PendingUser(db.Model):
    __tablename__ = 'pending_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    verification_token = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Functions
    
def generate_verification_token():
    return secrets.token_urlsafe(32)

def is_user_logged_in():
    # Example logic to check if the user is logged in
    # Replace this with your actual user authentication logic
    return True  # Replace with actual check


# Functioning of the web app

@app.route("/", methods=["GET"])
def home():
    if 'username' in session:
        return render_template("home.html")
    else:
        session.clear()
        return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    user_validate = False
    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        password_confirm = request.form.get("password-confirm")

        # Handling invalid Username input

        if not username or len(username) < 3:
            flash('Invalid Username', 'username_error')
            return render_template("register.html")

        username_db = db.session.scalars(db.select(User).filter_by(username = username)).first()
        
        if username_db is not None:
            flash('Username Already Exists', 'username_error')
            return render_template("register.html")
        

        # Handling invalid email adress
        if not email:
            flash('Email cannot be empty', 'email_error')
            return render_template('register.html')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format', 'email_error')
            return render_template('register.html')

        try:
            email_validator.validate_email(email)
        except email_validator.EmailNotValidError as e:
            flash('Invalid email: ' + str(e), 'email_error')
            return render_template('register.html')
    

        # Handling invalid Password input
        
        if not password or len(password) < 5 or len(password) > 20:
            flash('Invalid Password', 'password_error')
            return render_template("register.html")
        
        if password != password_confirm:
            flash("Passwords do not match", 'password_error')
            return render_template("register.html")

        new_user = User(username=username, password=password, email=email)

        verification_token = generate_verification_token()

        # Store the user in PendingUser temporarily until verification
        pending_user = PendingUser(username=username, password=password, email=email, verification_token=verification_token)
        db.session.add(pending_user)
        db.session.commit()

        # Generate an absolute URL
        verification_link = url_for('verify_email', token=verification_token, _external=True)

        msg = Message('Verify Your Email', recipients=[email])
        # msg.html = 
        # msg.body = f'Click {verification_link} to verify your email.'

        return redirect("/login")
    else:    
        return render_template("register.html")
    
@app.route("/email")
def email():
    return render_template("email.html")

if __name__ == "__main__":
    app.run(debug=True)