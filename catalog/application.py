#!/usr/bin/python2.7
from models import Base, User, Category, CategoryItem
from flask import Flask, jsonify, request, url_for, abort, \
    g, render_template, redirect, flash
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask import session as login_session

from flask_httpauth import HTTPBasicAuth
import json
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests


app = Flask(__name__)

# for Google auth flow
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Sports Category App"

auth = HTTPBasicAuth()

engine = create_engine(
    'sqlite:///catalog.db',
    connect_args={
        'check_same_thread': False})
Base.metadata.bind = engine

# create session
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# google connect auth flow with auth token
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '"style = "width: 300px; height: \
        300px;border-radius: 150px;-webkit-border-radius: \
        150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print "Logged in!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps(
                'Failed to revoke token for given user.',
                400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


# non-auth related routes
# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


def getCategoryId(category_name):
    # TODO change Category to Category
    category = session.query(Category).filter_by(name=category_name).one()
    return category.id


# Show catalog
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    # categories = session.query(Category).order_by(asc(Category.name))
    categories = session.query(Category)
    if 'username' not in login_session:
        return render_template('publiccatalog.html', categories=categories)
    else:
        return render_template('catalog.html', categories=categories)


# Show a categories items
# include string in route http://flask.pocoo.org/docs/0.12/quickstart/ >>
# Variable Rules
@app.route('/catalog/<string:category>/')
@app.route('/catalog/<string:category>/Items/')
def showCategoryItems(category):
    category = session.query(Category).filter_by(name=category).one()
    items = session.query(CategoryItem).filter_by(category=category).all()
    if 'username' not in login_session:
        return render_template(
            'publiccategoryitems.html',
            category=category,
            items=items)
    else:
        return render_template(
            'categoryitems.html',
            category=category,
            items=items)


# show individual items name, description...
@app.route('/catalog/<string:category>/<string:item_name>/')
def showCategoryItem(category, item_name):
    category = session.query(Category).filter_by(name=category).one()
    item_name = session.query(CategoryItem).filter_by(
        category=category, item_name=item_name).one()
    if 'username' not in login_session:
        return render_template(
            'publicitem.html',
            item_name=item_name,
            category=category)
    else:
        return render_template(
            'item.html',
            item_name=item_name,
            category=category)


@app.route('/catalog/<string:category>/<string:item_name>/JSON')
def itemJSON(category, item_name):
    category = session.query(Category).filter_by(name=category).one()
    item = session.query(CategoryItem).filter_by(
        category=category, item_name=item_name).one()
    return jsonify(item=item.serialize)


# Create a new category
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        # check for duplicates
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newcategory.html')


# Create a new category item
@app.route('/catalog/<string:category>/Items/new/', methods=['GET', 'POST'])
def newItem(category):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category).one()
    if request.method == 'POST':
        newItem = CategoryItem(
            item_name=request.form['name'],
            item_description=request.form['description'],
            user_id=login_session['user_id'],
            category_id=category.id)
        session.add(newItem)
        flash('New Item %s Item Successfully Created' % (newItem.item_name))
        session.commit()
        return redirect(url_for('showCategoryItems', category=category.name))
    else:
        return render_template('newitem.html', category=category)


# Edit an item
@app.route(
    '/catalog/<string:category>/<string:item_name>/edit/',
    methods=[
        'GET',
        'POST'])
def editItem(category, item_name):
    # need to use category in query in the case the item is in multiple
    # categories
    category_id = getCategoryId(category)
    editedItem = session.query(CategoryItem).filter_by(
        category_id=category_id, item_name=item_name).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized\
            to edit this item. Please create your own item in order\
            to edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.item_name = request.form['name']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited, changed to %s' % editedItem.item_name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'edititem.html',
            item_name=item_name,
            category=category)


# Delete an item
@app.route(
    '/catalog/<string:category>/<string:item_name>/delete/',
    methods=[
        'GET',
        'POST'])
def deleteItem(category, item_name):
    # TODO if item_name is in more than one category this would be incorrect...
    # need to use category in query in the case the item is in multiple
    # categories
    category_id = getCategoryId(category)
    itemToDelete = session.query(CategoryItem).filter_by(
        category_id=category_id, item_name=item_name).one()
    if 'username' not in login_session:
        return redirect('/login')
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
            to delete this item. Please create your own item in order \
            to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        flash('%s Successfully Deleted' % itemToDelete.item_name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'deleteitem.html',
            category=category,
            item_name=itemToDelete)


@app.route('/catalog.json')
def catalogJSON():
    # not the best that it returns all, query parameters could help make this
    # more flexible and usable.
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


if __name__ == '__main__':

    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
