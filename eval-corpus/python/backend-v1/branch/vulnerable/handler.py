from flask import Flask, request
import os
import sqlite3
import requests
import pickle
app = Flask(__name__)
@app.get('/review')
def handle():
    value = request.args.get('value')
    command = 'fixed'
    if value is not None:
        command = value
    os.system(command)
