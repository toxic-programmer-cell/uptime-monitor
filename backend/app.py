from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import schedule
import time
import os
import threading
from datetime import datetime, timedelta

#! Initialize the Flask app
app = Flask(__name__)

#! Configure the app
app.config[ 'SQLALCHEMY_DATABASE_URI' ] = 'sqlite:///uptime.db'
app.config[ 'SQLALCHEMY_TRACK_MODIFICATIONS' ] = False
app.config[ 'JWT_SECRET_KEY' ] = os.getenv('JWT_SECRET_KEY', 'fallback-for-testing')   #! Secret key Changed

#! Initialize the database and jwt
db = SQLAlchemy(app)
jwt = JWTManager(app)

#! Represents a user (admin or regular user) in the database.
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(255), nullable = False)
    phone_number = db.Column(db.String(20), nullable = False)
    country = db.Column(db.String(100), nullable = False)
    company_name = db.Column(db.String(100), nullable = True)
    is_admin = db.Column(db.Boolean, default = False)
    is_active = db.Column(db.Boolean, default = True)
    subscription_plan = db.Column(db.String(50), nullable = True)
    subscription_purchased = db.Column(db.DateTime, nullable = True)
    subscription_cancelled = db.Column(db.Boolean, default = False)
    subscription_end = db.Column(db.DateTime, nullable = True)
    websites = db.relationship('Website', backref = 'user', lazy = True)
    message = db.relationship('Message', backref = 'user', lazy = True)


#! Represents a website to monitor.
class Website(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    url = db.Column(db.String(200), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    status = db.Column(db.Boolean, default = True)
    response_time = db.Column(db.Float, default = 0.0)
    uptime_percentage = db.Column(db.Float, default = 100.0)
    checks = db.relationship('Check', backref = 'website', lazy = True)

#! Stores the history of each website check.
class Check(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable = False)
    timestamp = db.Column(db.DateTime, default = datetime.utcnow)
    status =  db.Column(db.Boolean, nullable = False)
    response_time = db.Column(db.Float, nullable = False)


#! Stores help messages sent by users to the admin.
class Message(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    content = db.Column(db.Text, nullable = False)
    timestamp = db.Column(db.DateTime, default = datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default = False)

#! Create database tables
with app.app_context():
    db.create_all()

#! - check_website(url): Checks if a website is up by sending an HTTP GET request.
def check_website(url):
    try:
        start_time = time.time()
        response = requests.get(url, timeout = 10)
        response_time = (time.time() - start_time) * 1000
        return response.status_code == 200, response_time
    except requests.RequestException:
        return False, 0.0
    
#! Background task to monitor websites
def monitor_websites():
    with app.app_context():
        websites = Website.query.all()
        for website in websites:
            user = User.query.get(website.user_id)
            if user and user.is_active and user.subscription_end and user.subscription_end > datetime.utcnow():
                status, response_time = check_website(website.url)
                website.status = status
                website.response_time = response_time
                checks = Check.query.filter_by(website_id = website.id).all()
                total_checks = len(checks) + 1
                up_checks = len([c for c in checks if c.status]) + (1 if status else 0)
                website.uptime_percentage = (up_checks / total_checks) * 100
                new_check = Check(website_id = website.id, status = status, response_time = response_time)
                db.session.add(new_check)
                db.session.commit()

#! Schedule monitoring every 5 minutes
schedule.every(5).minutes.do(monitor_websites)

#! Run scheduler in a separate thread
def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

#! - run_scheduler(): Runs the scheduler in a loop to execute scheduled tasks.
import threading
threading.Thread(target = run_scheduler, daemon = True).start()

#! Routes for Authentication
@app.route('/register', methods = ['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    country = data.get('country')
    company_name = data.get('company_name')

    #! Input validation
    if not email or not password or not phone_number or not country:
        return jsonify({'message': 'Email, password, phone number, country are required'}), 400
    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters'}), 400
    if User.query.filter_by(email = email).first():
        return jsonify({'message': 'Email already exists'}), 400
    

    #! Hash the password
    hashed_password = generate_password_hash(password, method = 'pbkdf2:sha256')

    user = User(
        email =  email,
        password = hashed_password,       #* changed: In production, hash the password!
        phone_number = phone_number,
        country = country,
        company_name = company_name,
        subscription_plan = None, # No subscription plan by default
        subscription_end = None
    )
    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Registration failed: {str(e)}'}), 500

#! - /login: Handles user and admin login.
@app.route('/login', methods = ['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Input validation
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    #query by email only
    user = User.query.filter_by(email = email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401     #! Check if user is correct
    
    if not user.is_active:
        return jsonify({'message': 'User is blocked'}), 403
    try:
        access_token = create_access_token(identity=str(user.id))
        return jsonify({'access_token': access_token, 'is_admin': user.is_admin}), 200
    except Exception as e:
        return jsonify({'message': f'Login failed: {str(e)}'}), 500


#! Routes for Admin
@app.route('/admin/users', methods = ['GET'])
@jwt_required()
def get_users():
    identity = get_jwt_identity()
    if not identity['is_admin']:
        return jsonify({'message': 'Admin access required'}), 403
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'email': u.email,
        'phone_number': u.phone_number,
        'country': u.country,
        'company_name': u.company_name,
        'is_admin': u.is_admin,
        'is_active': u.is_active,
        'subscription_plan': u.subscription_plan,
        'subscription_end': u.subscription_end.isoformat() if u.subscription_end else None
    }for u in users]), 200

#! /admin/users (POST): Allows the admin to add a new user.
@app.route('/admin/users', methods = ['POST'])
@jwt_required()
def add_user():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))  #Fetch user from DB
    if not user.is_admin:
        return jsonify({'message': 'Admin access required'}), 403
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    country = data.get('country')
    company_name = data.get('company_name')

    # Added: Input validation for reqquired fields
    if not email or not password or not phone_number or not country:
        return jsonify({'message': 'Email, password, phone number, country are required'}), 400
    
    # Added: Password length validation
    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters'}), 400
    
    if User.query.filter_by(email = email).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    # Hash the password before storing it
    hashed_password = generate_password_hash(password, method = 'pbkdf2:sha256')

    user = User(
        email = email,
        password = hashed_password,
        phone_number = phone_number,
        country = country,
        company_name = company_name,
        subscription_plan = None,
        subscription_end = None
    )

    #Try-exception block to handle database operations
    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User added successfully', 'user_id': user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Failed to add user: {str(e)}'}), 500
    
#! /admin/users/<user_id> (DELETE): Allows the admin to delete a user.
@app.route('/admin/users/<user_id>', methods = ['DELETE'])
@jwt_required()
def delete_user(user_id):
    admin_id = get_jwt_identity()
    admin = User.query.get(int(admin_id))
    #? Check if the user is an admin
    if not admin.is_admin:
        return jsonify({'message': 'Admin access required'}), 403
    
    user = User.query.get(user_id) # Fetch user from DB
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if user.is_admin:
        return jsonify({'message': 'Cannot delete admin'}), 403
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User delete successfully'}), 200
    except Exception as e:
        db.session.roolback()
        return jsonify({'message': f'Failed` to delete user: {str(e)}'}), 500

#! /admin/users/<user_id>/block (POST): Allows the admin to block a user.
@app.route('/admin/users/<user_id>/block', methods = ['POST'])
@jwt_required()
def block_user(user_id):
    admin_id = get_jwt_identity()
    admin = User.query.get(int(admin_id))
    if not admin.is_admin:
        return jsonify({'message': 'Admin access required'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if user.is_admin:
        return jsonify({'message': 'Cannot block admin'}), 403
    
    try:
        user.is_active = False
        db.session.commit()
        return jsonify({'message': 'User blocked successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Failed to block user: {str(e)}'}), 500


#! /admin/users/<user_id>/unblock (POST): Allows the admin to unblock a user.
@app.route('/admin/users/<user_id>/unblock', methods = ['POST'])
@jwt_required()
def unblock_user(user_id):
    admin_id = get_jwt_identity()      #*return string
    admin = User.query.get(int(admin_id))
    if not admin.is_admin:
        return jsonify({'message': 'Admin access required'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if user.is_admin:
        return jsonify({'message': 'Cannot unblock admin'}), 403
    try:
        user.is_active = True
        db.session.commit()
        return jsonify({'message': 'User unblocked successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Failed to unblock user: {str(e)}'}), 500

#! Subscription management routes
@app.route('/subscribe', methods = ['POST'])
@jwt_required()
def subscribe():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user.is_active:
        return jsonify({'message': 'User is blocked'}), 403
    
    #For now simulate a subscription (payment disabled)
    user.subscription_plan = 'basic'
    user.subscription_purchased = datetime.utcnow()
    user.subscription_end = datetime.utcnow() + timedelta(days = 30)

    try:
        db.session.commit()
        return jsonify({
            'message': 'Subscription successful',
            'subscription_purchased': user.subscription_purchased.isoformat(),
            'subscription_end': user.subscription_end.isoformat()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Subscription failed: {str(e)}'}), 500
    
#! Check subscription status
@app.route('/subscription', methods = ['GET'])
@jwt_required()
def get_subscription():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user.is_active:
        return jsonify({'message': 'User is blocked'}), 403
    
    return jsonify({
        'subscription_plan': user.subscription_plan,
        'subscription_purchased': user.subscription_purchased.isoformat() if user.subscription_purchased else None,
        'subscription_end': user.subscription_end.isoformat() if user.subscription_end else None
    }), 200

#! Cancle subscription
@app.route('/subscription/cancel', methods = ['POST'])
@jwt_required()
def cancel_subscription():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user.is_active:
        return jsonify({'message': 'User is blocked'}), 403
    
    if not user.subscription_plan:
        return jsonify({'message': 'No active subscription found'}), 400
    
    try:
        user.subscription_plan = None
        user.subscription_end = None
        db.session.commit()
        return jsonify({
            'message': 'Subscription cancelled successfully',
            'message': user.subscription_cancelled.isoformat(),
            }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Failed to cancel subscription: {str(e)}'}), 500


if __name__=='__main__':
    app.run(debug = True)