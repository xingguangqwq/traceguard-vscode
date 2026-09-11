from flask import Flask, request
import os
import sqlite3
import requests
import pickle
app = Flask(__name__)
@app.get('/review')
def handle():
    value = request.args.get('value')
    command = value
    if value is not None:
        command = 'fixed'
    else:
        command = 'fallback'
    os.system(command)
