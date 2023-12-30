from config import GOOGLE_RECAPTCHA_API_KEY, GOOGLE_RECAPTCHA_SITE_KEY, Tasky_secret_key
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
from flask import Flask, session, redirect, render_template, request, flash, url_for, Markup, abort, jsonify
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
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    tasks = db.relationship('Task', backref='projects', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):

    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(150), nullable=False)
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
    
# Custom function to add 'now' to Jinja2 context
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}


# Functioning of the web app

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        pass

    else:

        projects = current_user.projects
        username = current_user.username

        return render_template("home.html", projects=projects, username=username)

@app.route("/project-<int:project_id>/<string:project_name>", methods=["GET", "POST"])
@login_required
def project_dashboard(project_id, project_name):
    if request.method == "POST":
        # Get the list of completed task IDs from the form
        completed_task_ids = request.form.getlist('completed_tasks[]', type=int)

        # Update tasks as complete or incomplete in the database based on received IDs
        tasks = Task.query.filter_by(project_id=project_id).all()
        for task in tasks:
            task.completed = task.id in completed_task_ids
            db.session.commit()

        return redirect(url_for('project_dashboard', project_id=project_id, project_name=project_name))

    else:
        project = Project.query.get_or_404(project_id)
        tasks = Task.query.filter_by(project_id=project_id).all()

        return render_template("dashboard.html", project=project, tasks=tasks, username=current_user.username)

@app.route("/project-<int:project_id>/<string:project_name>/add-task", methods=["GET", "POST"])
@login_required
def add_task(project_id, project_name):
    if request.method == "POST":

        tasks = request.form.getlist('task[]')

        for task in tasks:
            if not task:
                task = None
                continue

            if task.isspace():
                task = None
                continue
            
            if len(task) > 150:
                flash('Task must be less than 150 characters.', 'input_error')
                return redirect(url_for('add_task', project_id=project_id, project_name=project_name))      
        
            new_task = Task(description=task, project_id=project_id)

            db.session.add(new_task)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            flash('An error occured while adding the tasks.', 'error')
            return redirect(url_for('add_task', project_id=project_id, project_name=project_name))

        return redirect(url_for("project_dashboard", project_id=project_id, project_name=project_name))
    else:
        project = Project.query.get_or_404(project_id)
        username = current_user.username
        
        return render_template("add-task.html", project=project, username=username)
    

@app.route('/edit-task/<int:task_id>', methods=["GET", "POST"])
def edit_task(task_id):
    if request.method == 'POST':
        task = Task.query.get(task_id)
        project_id = task.project_id
        project_name = Project.query.filter_by(id=project_id).first().name

        new_description = request.form.get('task-edit')

        if not new_description or new_description.isspace():
            return redirect(url_for("project_dashboard", project_id=project_id, project_name=project_name))
        
        if len(new_description) > 150:
            flash('Task must be less than 150 characters.', 'input_error')
            return redirect(url_for('edit_task', task_id = task_id))      

        task.description = new_description

        try:
            db.session.commit()
        except:
            db.session.rollback()
            flash('An error occured while editing the task. Try Again', 'error')
            return redirect(url_for('edit_task', project_id=project_id, project_name=project_name))

        try:
            db.session.commit()
        except:
            db.session.rollback()
            flash('An error occured while adding the tasks.', 'error')
            return redirect(url_for('add_task', project_id=project_id, project_name=project_name))
        
        return redirect(url_for("project_dashboard", project_id=project_id, project_name=project_name))

    else:
        task_info = Task.query.filter_by(id=task_id).first()
        current_task_description = task_info.description
        project_id = task_info.project_id
        project_name = Project.query.filter_by(id=project_id).first().name

        return render_template('edit-task.html', task_id=task_id, current_task_description=current_task_description, project_name=project_name, project_id=project_id)
    
@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task:
        # Perform deletion from the database using SQLAlchemy
        db.session.delete(task)
        db.session.commit()
        return jsonify({'message': 'Task deleted successfully'})
    else:
        return jsonify({'error': 'Task not found'}), 404


@app.route("/delete_project/<int:project_id>", methods=["DELETE"])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)

    db.session.delete(project)
    db.session.commit()

    return jsonify({'message': 'Project deleted successfully'})

@app.route("/add-proyect", methods=["GET", "POST"])
@login_required
def add_project():
    if request.method == "POST":
        project_name = request.form.get('project')
        description = request.form.get('description')
        user_projects = current_user.projects

        if len(user_projects) >= 6:
            flash("You have reached the maximum limit of projects. Please delete one to add a new project.", "warning")
            return redirect(url_for("add_project"))      

        if not project_name:
            flash('Project cannot be empty.', 'input_error')
            return redirect(url_for('add_project'))
        
        if len(project_name) > 100:
            flash('Project name must be less than 100 characters.', 'input_error')
            return redirect(url_for('add_project'))
        
        # Trim leading and trailing spaces
        trimmed_name = project_name.strip()
        
        # Check if the name is empty or contains more than one space between words
        words = trimmed_name.split()

        if len(words) > 1 and any(len(word) == 0 for word in words[1:]):
            flash('Invalid project name.', 'input_error')
            return redirect(url_for('add_project'))
        
        project_name = trimmed_name

        if len(description) > 200:
            flash('The project description must be less than 200 characters.', 'input_error')
            return redirect(url_for('add_project'))
        
        if description.isspace():
            description = None

        try:
            project_name = project_name.capitalize()
        except:
            pass

        try:
            description = description.capitalize()
        except:
            pass


        username = session["username"]
        user_id=User.query.filter_by(username=username).first().id
        project = Project(user_id=user_id, name=project_name, description=description)

        db.session.add(project)

        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            flash('An error has occured adding the project. Try Again.', 'input_error')
            return redirect(url_for('add_project'))

        return redirect(url_for('home'))

    else:
        username = current_user.username
        return render_template("add-project.html", username=username)





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
            flash('Enter a valid email.', 'email_error')
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