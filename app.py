from flask import Flask, session, redirect, render_template, request, flash
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from config import kc

app = Flask(__name__)

app.secret_key = kc

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db' # Database for app data (default db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

db = SQLAlchemy(app)

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

class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_name = db.Column(db.String(100), nullable=False)
    user = db.relationship('User', backref='tasks')  # Establish a relationship with the User table

# Function to check if user is logged in
def is_user_logged_in():
    # Example logic to check if the user is logged in
    # Replace this with your actual user authentication logic
    return True  # Replace with actual check

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
        password = request.form.get("password")
        password_confirm = request.form.get("password-confirm")

        if not username or len(username) < 3:
            flash('Invalid Username', 'error')
            return render_template("register.html")

        username_db = db.session.scalars(db.select(User).filter_by(username = username)).first()
        
        if username_db.username == username:
            flash('Username Already Exists', 'error')
            return render_template("register.html")
        
        if not request.form.get("password") or len(password) < 5 or len(password) > 20:
            flash('Invalid Password', 'error')
            return render_template("register.html")
        
        if request.form.get("password") != request.form.get("password-confirm"):
            hola = hola

        
        return redirect("/login")
    else:    
        return render_template("register.html")

if __name__ == "__main__":
    app.run(debug=True)