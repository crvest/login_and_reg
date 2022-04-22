from crypt import methods
from re import U
from flask import render_template, redirect, request, session, flash
from flask_app import app
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

# index route
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    # test for failure of basic validations
    if not User.validate_register(request.form):
        return redirect('/')
    # collect data for query, including hashing pw
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    query_data = {
        'first_name' : request.form['first_name'],
        'last_name' : request.form['last_name'],
        'email' : request.form['email'],
        'password' : pw_hash
    }
    # add user data to db
    user_id = User.register_user(query_data)
    # log user in via session
    session['user_id'] = user_id
    # redirect to welcome message
    return redirect('/dashboard')

# login  route
@app.route('/login', methods=['POST'])
def login():
    # test for failure of basic validations
    if not User.validate_login(request.form):
        return redirect('/')
    # log user in via session
    logged_user = User.get_by_email(request.form)
    session['user_id'] = logged_user.id
    # redirect to welcome message
    return redirect('/dashboard')

# dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login or register to continute')
        return redirect('/')
    query_data = {
        'user_id' : session['user_id']
    }
    user = User.get_by_id(query_data)
    return render_template('dashboard.html', user = user)

# logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
