from flask import Flask, session, redirect, render_template, request
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db' # Database for app data (default db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

db = SQLAlchemy(app)

# Configure Flask-Session to use SQLAlchemy for session storage
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'

# Initialize Flask-Session
Session(app)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_name = db.Column(db.String(100), nullable=False)
    user = db.relationship('User', backref='tasks')  # Establish a relationship with the User table


@app.route("/")
def inicio():
    session.clear()
    return render_template("layout.html")


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)