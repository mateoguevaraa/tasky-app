from config import GOOGLE_RECAPTCHA_API_KEY, GOOGLE_RECAPTCHA_SITE_KEY, Tasky_secret_key
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
from flask import Flask, session, redirect, render_template, request, flash, url_for, Markup, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
import dns.resolver
import os
import re
import requests

app = Flask(__name__)

app.secret_key = Tasky_secret_key

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db' # Database for app data (default db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

db = SQLAlchemy(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure Flask-Session to use SQLAlchemy for session storage
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'

# Initialize Flask-Session
Session(app)

# Tables
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    projects = db.relationship('Project', backref='users', lazy=True)

class Project(db.Model):

    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(25), nullable=False)
    tasks = db.relationship('Task', backref='projects', lazy=True)

class Task(db.Model):

    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)

GOOGLE_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

# Functions
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_recaptcha(recaptcha_response):

    secret_key = GOOGLE_RECAPTCHA_SITE_KEY

    # Validate the reCAPTCHA response using Google API
    import requests
    payload = {
        'response': recaptcha_response,
        'secret': secret_key
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()

    return result['success']

def validate_user_input(username):
    # Define the regular expression pattern for username validation
    pattern = r'^[a-zA-Z0-9_.]+$'  # Alphanumeric with '.', '_' allowed
    
    return bool(re.match(pattern, username))

def is_valid_email_domain(email):
    try:
        domain = email.split('@')[1]
        # Query the MX records for the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        return True if mx_records else False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False


# Functioning of the web app

@app.route("/home", methods=["GET", "POST", "DELETE"])
@login_required
def home():
    if request.method == "POST":
        pass
    else:
        projects=current_user.projects
        username=current_user.username
        return render_template("dashboard.html", projects=projects, username=username)


@app.route("/edit-task", methods=["GET", "POST", "DELETE"])
@login_required
def edit():
    if request.method == "POST":
        pass
    else:
        return render_template("dashboard2.html", projects=projects, username=username)

@app.route("/add-proyect", methods=["GET", "POST"])
@login_required
def add_project():
    if request.method == "POST":
        project_name = request.form.get('project')

        if not project_name:
            flash('Project cannot be empty.', 'input_error')
            return redirect(url_for('register'))
        
        if len(project_name) > 25:
            flash('Project name must be less than 25 characters.', 'input_error')
            return redirect(url_for('register'))
        
        # Trim leading and trailing spaces
        trimmed_name = project_name.strip()
        
        # Check if the name is empty or contains more than one space between words
        words = trimmed_name.split()

        if len(words) > 1 and any(len(word) == 0 for word in words[1:]):
            flash('Invalid project name.', 'input_error')
            return redirect(url_for('add_project'))
        
        project_name = trimmed_name
        print(project_name)

        username = session["username"]
        user_id=User.query.filter_by(username=username).first().id
        project = Project(user_id=user_id, name=project_name)

        db.session.add(project)

        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            flash('An error has occured adding the project. Try Again.', 'input_error')
            return redirect(url_for('add_project'))

        return redirect(url_for('home'))

    else:
        return render_template("add-project.html")





@app.route("/", methods=["GET", "POST"])
def index():
    if "username" in session:
        return redirect(url_for('home'))
    else:
        session.clear()
        return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username').lower()
        password = request.form.get('password')
        log_me_out = request.form.get('log-out-button')  # Check if "Log out after" is selected

        # Check if username and password are provided
        if not username or not password:
            flash('Please provide both username and password.', 'error')
            return redirect(url_for('login'))
        else:
            # Query the user from the database
            user = User.query.filter_by(username=username).first()

            if user:
                # Validate password
                if check_password_hash(user.password, password):
                    # Password is correct, set the user in the session
                    session['username'] = user.username

                    if log_me_out:
                        session.permanent = False  # Log out after closing the browser
                    else:
                        session.permanent = True  # Stay logged in even after closing the browser
                    
                    login_user(user)

                    return redirect(url_for('home'))  # Redirect to the home page or dashboard
                else:
                    flash('Incorrect password. Please try again.', 'error')
                    return redirect(url_for('login'))
            else:
                flash('User does not exist. Please <a href="/register" style="color:inherit;">register</a>.', 'error')
                return redirect(url_for('login'))
    else:
        if "username" in session:
            return redirect(url_for('home'))
        else:
            return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form.get("username").lower()
        email = request.form.get("email")
        password = request.form.get("password")
        password_confirm = request.form.get("password-confirm")

        # Handling invalid Username input

        if not username:
            flash('Username cannot be empty.', 'username_error')
            return redirect(url_for('register'))
        
        if len(username) <= 20 and len(username) >= 3:
            pass
        else:
            flash('Username must be between 3 and 20 characters', 'username_error')
            return redirect(url_for('register'))

        if validate_user_input(username):
            pass
        else:
            flash('Username can only contain letters, numbers, ".", or "_".', 'username_error')
            return redirect(url_for('register'))

        username_db = db.session.scalars(db.select(User).filter_by(username = username)).first()
        
        if username_db is not None:
            flash('Username Already Exists.', 'username_error')
            return redirect(url_for('register'))
        
        # Handling invalid Password input
        
        if ' ' in password:
            flash('Invalid Password.', 'password_error')
            return redirect(url_for('register'))
        
        if not password or len(password) < 5 or len(password) > 20:
            flash('Invalid Password.', 'password_error')
            return redirect(url_for('register'))
        
        if password != password_confirm:
            flash("Passwords do not match.", 'password_error')
            return redirect(url_for('register'))
        
        password_hash = generate_password_hash(password)


        # Handling invalid email adress

        if not email:
            flash('Email cannot be empty.', 'email_error')
            return redirect(url_for('register'))

        try:
            email_info = validate_email(email)
            email = email_info.normalized

        except EmailNotValidError as e:
            flash('Invalid email: ' + str(e), 'email_error')
            return redirect(url_for('register'))
        
        result = is_valid_email_domain(email)

        if result:
            pass
        else:
            flash('Could not find the specified email adress.', 'email_error')
            return redirect(url_for('register'))
        
        # Check if email already exists in pending_users table
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists! Try another.', 'email_error')
            return redirect(url_for('register'))
    
        # Store the user in user table
    
        user = User(username=username, password=password_hash, email=email)

        db.session.add(user)
    
        try:
            db.session.commit()
            secret_response = request.form['g-recaptcha-response']
            verify_response = requests.post(
                url=f'{GOOGLE_VERIFY_URL}?secret={GOOGLE_RECAPTCHA_API_KEY}&response={secret_response}').json()
            print(verify_response)
            # Check Google response. If success == False or score < 0.5, most likely a robot -> abort
            if not verify_response['success'] or verify_response['score'] < 0.5:
                flash('An unexpected error occured during registration. Try again', 'register_error')
                return redirect(url_for('register'))

            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()

            flash('An unexpected error occured during registration. Try again', 'register_error')
            return redirect(url_for('register'))
    else:
        if "username" in session:
            return redirect(url_for('home'))
        else:
            return render_template("register.html", GOOGLE_RECAPTCHA_SITE_KEY=GOOGLE_RECAPTCHA_SITE_KEY)
    
@app.route('/logout')
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)