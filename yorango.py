from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from models import *
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import logging

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

@app.route('/listings')
def listings(): 
    sort_order = request.args.get('sort', 'list')
    price_low = request.form['price_low']
    price_high = request.form['price_high']
    size_max = request.form['size_max']
    size_min = request.form['size_min']
    num_rooms_max = request.form['num_rooms_max']
    num_rooms_min = request.form['num_rooms_min']
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

@app.route('/listings/<listing_id>', methods=['GET', 'POST'])
def show_listing(listing_id):
    return 'Listing %s' % listing_id

@app.route('/users')
def users():
    users = User.objects.all()
    return render_template('users.html', u=users)

@app.route('/users/<user_id>', methods=['GET', 'POST'])
def show_user_profile(user_id):
    # show the user profile for that user
    return 'User %s' % user_id

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        error = None
        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        elif User.objects.get(email=request.form['email']):
            error = 'User with email `{0}` is already registered.'.format(email)
        if error is None:
            new_user = User(email=email, password=bcrypt.generate_password_hash(password))
            new_user.first_name = request.form['first_name']
            new_user.last_name = request.form['last_name']
            new_user.is_admin = request.form['is_admin']
            new_user.is_client = request.form['is_client']
            new_user.is_realtor = request.form['is_realtor']
            new_user.save()
            return redirect(url_for('login'))
        else:
            flash(error)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        try:
            this_user = User.objects.get(email=request.form['email'])
            if request.form['email'] != this_user.email:
                error = 'Invalid email'
            elif bcrypt.check_password_hash(this_user.password, request.form['password']) == False:
                error = 'Invalid password'
            else:
                session['logged_in'] = True
                session['this_user'] = {'first_name': this_user.first_name}

                flash('You were logged in')
                return redirect(url_for('index'))
        except:
            flash('User does not exist')
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.debug = app.config['DEBUG']
    app.run()
