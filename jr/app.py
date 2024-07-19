from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from bson import ObjectId
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '6466e92373e97a194d2126c8dac0da2f')  # Use environment variable for security
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/notes_db')  # Use environment variable for security
mongo = PyMongo(app)

# Middleware to verify JWT token
@app.before_request
def check_authentication():
    if 'username' not in session and request.endpoint not in ['login', 'register']:
        return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' in session:
        notes = mongo.db.notes.find({'username': session['username']})
        return render_template('index.html', notes=notes)
    return redirect(url_for('login'))

@app.route('/add_note', methods=['POST'])
def add_note():
    if 'username' in session:
        title = request.form.get('title')
        content = request.form.get('content')
        mongo.db.notes.insert_one({'title': title, 'content': content, 'username': session['username']})
        flash('Note added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/edit_note/<note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    if 'username' in session:
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            mongo.db.notes.update_one({'_id': ObjectId(note_id)}, {'$set': {'title': title, 'content': content}})
            flash('Note updated successfully!', 'success')
            return redirect(url_for('index'))
        note = mongo.db.notes.find_one({'_id': ObjectId(note_id)})
        return render_template('edit_note.html', note=note)
    return redirect(url_for('login'))

@app.route('/delete_note/<note_id>')
def delete_note(note_id):
    if 'username' in session:
        mongo.db.notes.delete_one({'_id': ObjectId(note_id)})
        flash('Note deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = mongo.db.users.find_one({'username': username})
        if user:
            if check_password_hash(user['password'], password):
                session['username'] = username
                return redirect(url_for('index'))
            flash('Invalid password', 'danger')
        else:
            flash('User not found. Please register.', 'info')
            return redirect(url_for('register'))  # Redirect to register page if the user does not exist
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = mongo.db.users.find_one({'username': username})
        if user:
            flash('Username already exists', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  # Updated method
            mongo.db.users.insert_one({'username': username, 'password': hashed_password})
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
