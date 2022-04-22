from flask_app.config.mysqlconnection import connectToMySQL
from flask_app import app
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
from flask import flash
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class User:
    def __init__(self, data):
        self.id = data['id']

        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']

        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    # validate registration
    @staticmethod
    def validate_register(form_data):
        is_valid = True
        if len(form_data['first_name']) < 3:
            flash("First name must be at least 3 characters.")
            is_valid = False
        if len(form_data['last_name']) < 3:
            flash("Last name must be at least 3 characters.")
            is_valid = False
        # tests for correct email format: ______@_____.___
        if not EMAIL_REGEX.match(form_data['email']):
            flash("Email must be in valid email format")
            is_valid = False
        if len(form_data['password']) < 8:
            flash("Password must be at least 8 characters.")
            is_valid = False
        # test for pw and conf_pw match
        if form_data['password'] != form_data['conf_pw']:
            flash("Password and password confirmation do not match.")
            is_valid = False
        return is_valid
    
    # validate login
    @staticmethod
    def validate_login(form_data):
        is_valid = True
        user_in_db = User.get_by_email(form_data)
        # test if user email is already registered in db
        if not user_in_db:
            flash('Invalid Email/Password')
            is_valid = False
        # check password if user is in db
        elif not bcrypt.check_password_hash(user_in_db.password, form_data['password']):
            flash('Invalid Email/Password')
            is_valid = False
        return is_valid


    @classmethod
    def register_user(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
        result = connectToMySQL('login_and_reg').query_db(query, data)
        return result
    
    @classmethod
    def get_by_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL('login_and_reg').query_db(query, data)
        if len(result) < 1:
            return False
        return cls(result[0])

    @classmethod
    def get_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(user_id)s;"
        result = connectToMySQL('login_and_reg').query_db(query, data)
        if len(result) < 1:
            return False
        return cls(result[0])
