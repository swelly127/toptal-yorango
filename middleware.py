import bson

from flask import request, redirect, url_for, render_template, flash
from functools import wraps

from helpers import *
from models import *

from user_agents import parse

def is_web_browser():
    user_agent = parse(request.headers.get('User-Agent'))
    return user_agent.browser.family != "Other"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_browser = is_web_browser()
        current_user = get_current_user()
        if type(current_user) is str:
            if is_browser:
                return render_template('base.html', baseMsg=current_user), 401
            return current_user, 401
        if current_user is None:
            if is_browser:
                return redirect(url_for('login', next=request.url))
            return "Missing access token", 403
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_browser = is_web_browser()
        current_user = get_current_user()
        if type(current_user) is str:
            if is_browser:
                return render_template('base.html', baseMsg=current_user), 401
            return current_user, 401
        if current_user is None:
            if is_browser:
                flash('This action is only allowed for site admins. Please login to an admin account.')
                return redirect(url_for('login', next=request.url))
            return "Missing access token", 403
        elif current_user['role'] < 2:
            if is_browser:
                flash('This action is only allowed for site admins.')
                return redirect(url_for('index'))
            return 'This action is only allowed for site admins.', 403
        else:
            return f(*args, **kwargs)
    return decorated_function

def realtor_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_browser = is_web_browser()
        current_user = get_current_user()
        if type(current_user) is str:
            if is_browser:
                return render_template('base.html', baseMsg=current_user), 401
            return current_user, 401
        if current_user is None:
            if is_browser:
                flash('Please login to an admin or realtor account.')
                return redirect(url_for('login', next=request.url))
            return 'Missing access token.', 403
        elif current_user['role'] < 1:
            if is_browser:
                flash('Please login to an admin or realtor account.')
                return redirect(url_for('login', next=request.url))
            return "Permission denied. This action is only allowed for realtors and site admins.", 403
        else:
            return f(*args, **kwargs)
    return decorated_function

def find_listing(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        listing_id = kwargs.get('listing_id', None)
        if listing_id:
            if not bson.objectid.ObjectId.is_valid(listing_id):
                return "Invalid listing id.", 400
            listing = Listing.objects(id=listing_id).first()
            if not listing:
                return "Listing not found.", 404
            request.listing = listing
        return f(*args, **kwargs)
    return decorated_function

def find_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = kwargs.get('user_id', None)
        if user_id:
            if not bson.objectid.ObjectId.is_valid(user_id):
                return "Invalid user id.", 400
            user = User.objects(id=user_id).first()
            if not user:
                return "User not found.", 404
            request.user = user
        return f(*args, **kwargs)
    return decorated_function
