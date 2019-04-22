from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from models import *
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import logging
import os

os.environ["MONGOLAB_URI"]="mongodb://jshu:sushi4ever@ds145456.mlab.com:45456/heroku_5kgg2qvt"
os.environ["MONGOLAB_DB"]="mongolab-polished-82927"

mongo_host = os.getenv('MONGOLAB_URI', 'mongodb://localhost:27017')
connect(alias='default', host=mongo_host)

app = Flask(__name__)
app.config.from_object('settings')
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

@app.route('/')
def index():
    if session.get('logged_in', False):
        listings = Listing.objects.all()
        return render_template('index.html', listings=listings)
    return redirect(url_for('login'))

@app.route('/listings', methods=['GET', 'POST'])
def listings():
    if request.method == 'POST':
        # Create a new listing
        return redirect(url_for('listings'))
    sort_order = request.args.get('sort', 'list')
    price_low = request.form.get('price_low')
    price_high = request.form.get('price_high')
    size_max = request.form.get('size_max')
    size_min = request.form.get('size_min')
    num_rooms_max = request.form.get('num_rooms_max')
    num_rooms_min = request.form.get('num_rooms_min')
    listings = Listing.objects(
        monthly_rent__lte=price_high, 
        monthly_rent__gte=price_low, 
        sq_ft__lte=size_max,
        sq_ft__gte=size_min,
        num_rooms__lte=num_rooms_max,
        num_rooms__gte=num_rooms_min,
    )
    if (sort_order == "map"):
        return render_template('map.html', listings=listings)
    else:
        return render_template('listings.html', listings=listings)

@app.route('/listings/new')
def listing_form():
    return render_template('listing_form.html')

@app.route('/listings/<listing_id>', methods=['GET', 'PUT', 'DELETE'])
def single_listing(listing_id):
    if request.method == 'PUT':
        return None
    if request.method == 'DELETE':
        Listing.objects(id=listing_id).delete()
        flash('Listing has been deleted.')
        return redirect(url_for('listings'))
    return 'Listing %s' % listing_id

@app.route('/users')
def users():
    users = User.objects.all()
    return render_template('users.html', u=users)

@app.route('/users/<user_id>', methods=['GET', 'PUT', 'DELETE'])
def single_user(user_id):
    if request.method == 'PUT':
        return None
    if request.method == 'DELETE':
        User.objects(id=user_id).delete()
        flash('User account has been deleted.')
        return redirect(url_for('users'))
    return 'User %s' % user_id

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email:
            return flash('Email is required.')
        elif not password:
            return flash('Password is required.')
        elif User.objects(email=email).first():
            return flash('User with email `{0}` is already registered.'.format(email))
        new_user = User(email=email, password=bcrypt.generate_password_hash(password))
        new_user.first_name = request.form.get('first_name')
        new_user.last_name = request.form.get('last_name')
        print(request.form.get('is_admin'), request.form.get('is_realtor'))
        new_user.is_admin = request.form.get('is_admin') == "true"
        new_user.is_realtor = request.form.get('is_realtor') == "true"
        new_user.save()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email:
            return flash('Email is required.')
        elif not password:
            return flash('Password is required.')
        this_user = User.objects.get(email=email)
        if not this_user:
            return flash('User does not exist.')
        if email != this_user.email:
            error = 'Invalid email'
        elif bcrypt.check_password_hash(this_user.password, password) == False:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            session['this_user'] = {
                'id': this_user.id,
                'first_name': this_user.first_name,
                'is_admin': this_user.is_admin,
            }
            flash('You are now logged in.')
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('this_user', None)
    flash('You are now logged out.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.debug = app.config['DEBUG']
    app.run()
