import bson

from flask import request, redirect, url_for, render_template, flash
from functools import wraps

from helpers import *
from models import *

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if type(current_user) is str:
            return current_user, 401
        if current_user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if type(current_user) is str:
            return current_user, 401
        if current_user is None:
            flash('This action is only allowed for site admins. Please login to an admin account.')
            return redirect(url_for('login', next=request.url))
        elif current_user['role'] < 2:
            flash('This action is only allowed for site admins.')
            return redirect(url_for('index'))
        else:
            return f(*args, **kwargs)
    return decorated_function

def realtor_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if type(current_user) is str:
            return current_user, 401
        if current_user is None:
            flash('This action is only allowed for site admins. Please login to an admin or realtor account.')
            return redirect(url_for('login', next=request.url))
        elif current_user['role'] < 1:
            flash('This action is only allowed for site admins and realtors.')
            return "Permission denied", 403
        else:
            return f(*args, **kwargs)
    return decorated_function

def find_listing(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        listing_id = kwargs.get('listing_id', None)
        if listing_id:
            if not bson.objectid.ObjectId.is_valid(listing_id):
                flash('This is not a valid listing id.')
                return render_template('base.html', baseMsg="Invalid listing id."), 404
            listing = Listing.objects(id=listing_id).first()
            if not listing:
                flash('Listing not found.')
                return render_template('base.html', baseMsg="Listing not found."), 404
            request.listing = listing
        return f(*args, **kwargs)
    return decorated_function

def find_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = kwargs.get('user_id', None)
        if user_id:
            if not bson.objectid.ObjectId.is_valid(user_id):
                flash('This is not a valid user id.')
                return render_template('base.html', baseMsg="Invalid user id."), 404
            user = User.objects(id=user_id).first()
            if not user:
                flash('User not found.')
                return render_template('base.html', baseMsg="User not found."), 404
            request.user = user
        return f(*args, **kwargs)
    return decorated_function
