import os

from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sessions.db'
app.config['SESSION_TYPE'] = 'sqlalchemy'

db = SQLAlchemy(app)

app.config['SESSION_SQLALCHEMY'] = db

sess = Session(app)

@app.route("/")
def inicio():
    return 'ok'