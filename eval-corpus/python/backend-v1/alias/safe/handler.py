from flask import Flask, request
import os
import sqlite3
import requests
import pickle
app = Flask(__name__)
@app.get('/review')
def handle():
    value = request.args.get('value')
    alias = value
    command = 'fixed'
    os.system(command)
