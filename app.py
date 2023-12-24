from datetime import datetime
from email_validator import validate_email, EmailNotValidError
from flask import Flask, session, redirect, render_template, request, flash, url_for
from flask_mail import Mail, Message
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
import dns.resolver
import os
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

def is_valid_email_domain(email):
    try:
        domain = email.split('@')[1]
        # Query the MX records for the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        return True if mx_records else False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False

def send_email(recipient_email, username, verification_link, subject):
    message = Mail(
        from_email='taskyapp@homemail.com',
        to_emails=recipient_email,
        subject=subject,
        html_content= render_template("email.html", username=username, verification_link=verification_link))
    
    try:
        sg = SendGridAPIClient(os.environ.get('SendGrid_key'))
        response = sg.send(message)
        return True
    except Exception as e:
        return False

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
    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        password_confirm = request.form.get("password-confirm")

        # Handling invalid Username input

        if not username or len(username) < 3:
            flash('Invalid Username.', 'username_error')
            return render_template("register.html")

        username_db = db.session.scalars(db.select(User).filter_by(username = username)).first()
        
        if username_db is not None:
            flash('Username Already Exists.', 'username_error')
            return render_template("register.html")
        

        # Handling invalid email adress
        if not email:
            flash('Email cannot be empty.', 'email_error')
            return render_template('register.html')

        try:
            email_info = validate_email(email)
            email = email_info.normalized

        except EmailNotValidError as e:
            flash('Invalid email: ' + str(e), 'email_error')
            return render_template('register.html')
        
        result = is_valid_email_domain(email)

        if result:
            pass
        else:
            flash('Could not find the specified email adress.', 'email_error')
            return render_template('register.html')
        
        # Check if email already exists in pending_users table
        existing_email = PendingUser.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists! Try another.', 'email_error')
            return render_template("register.html")


        # Handling invalid Password input
        
        if not password or len(password) < 5 or len(password) > 20:
            flash('Invalid Password.', 'password_error')
            return render_template("register.html")
        
        if password != password_confirm:
            flash("Passwords do not match.", 'password_error')
            return render_template("register.html")
        
        password_hash = generate_password_hash(password)
    
        # Store the user in PendingUser temporarily until verification

        verification_token = generate_verification_token()

        pending_user = PendingUser(username=username, password=password_hash, email=email, verification_token=verification_token)

        db.session.add(pending_user)
    
        try:
            db.session.commit()

            # Generate an absolute URL
            verification_link = url_for('verify_email', token=verification_token, _external=True)

            if send_email(email, username, verification_link, 'Activate Your Tasky Account'):
                pass
            else:
                flash('An unexpected error occured during registration. Try again', 'register error')
                return render_template("register.html")

            flash('Verification email sent! Please check your inbox.', 'success')
            return render_template("success.html")
        
        except IntegrityError as e:
            db.session.rollback()

            flash('An unexpected error occured during registration. Try again', 'register error')
            return render_template("register.html")

    else:    
        return render_template("register.html")
    
@app.route('/verify/<token>')
def verify_email(token):
    pending_user = PendingUser.query.filter_by(verification_token=token).first()
    if pending_user:
        # Move the pending user to the User table after verification
        new_user = User(username=pending_user.username, password=pending_user.password, email=pending_user.email, created_at=pending_user.created_at)
        db.session.add(new_user)
        db.session.delete(pending_user)
        db.session.commit()

        flash('Your email has been verified. You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid or expired verification token.', 'error')
        return redirect(url_for('register'))  # Redirect to the register page with an error flash message
    
@app.route("/email")
def email():
    return render_template("email.html")

@app.route("/success")
def success():
    return render_template("success.html")

if __name__ == "__main__":
    app.run(debug=True)