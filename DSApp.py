##
## DSApp.py
##
## A simple Data Steward Application using Python and Flask
##

"""
Contents:
    1. Imports
    2. Configs
    3. Forms
    4. Models
    5. Routes & Errors
    6. Helper Functions
    7. Run
"""

#
# 1. Imports
#
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, abort, flash
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form, html5
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, \
    login_required, current_user
from flask.ext.script import Manager
from flask.ext.script import Shell

#
# 2. Configs
#
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'
app.config['SQLALCHEMY_DATABASE_URI'] =\
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
#
manager = Manager(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)
lm.login_view = 'login'


#
# 3. Forms
#
class LoginForm(Form):
    login_id = StringField('Login ID', validators=[Required(), Length(3, 6)])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Submit')
  

#
# 4. Models
#
class User(UserMixin, db.Model):
    """A Data Steward - an end-user of the DSApp"""
    __tablename__ = 'dsapp_users'
    id = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.String(6), index=True, unique=True)
    password_hash = db.Column(db.String(64))
    last_seen_dttm = db.Column(db.DateTime)
    entities = db.relationship('Entity', backref='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def register(login_id, password):
        user = User(login_id=login_id)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    def __repr__(self):
        return '<User {0}>'.format(self.login_id)


class Entity(db.Model):
    """An abstraction of an entity
    that is modifiable by some Data Steward
    through the DSApp"""
    __tablename__ = 'dsapp_entities'
    id = db.Column(db.Integer, primary_key=True)
    entity_nm = db.Column(db.String(36), index=True, unique=True)
    ds_table_nm = db.Column(db.String(36), index=True, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('dsapp_users.id'))

    @staticmethod
    def register(entity_nm, ds_table_nm, user_id):
        entity = Entity(entity_nm=entity_nm, ds_table_nm=ds_table_nm, user_id=user_id)
        db.session.add(entity)
        db.session.commit()
        return entity

    def __repr__(self):
        return '<Entity {0}>'.format(self.entity_nm)

## DS Models


class MAG_BAG(db.Model):
    """An entity used for the test_setup"""
    __tablename__ = 'DS_MAG_BAG'
    BAG_ABBREV = db.Column(db.String(18), primary_key=True)
    BAG_NM = db.Column(db.String(128))
    MAGIC_POWER_DESCR = db.Column(db.String(256))
    SORT_ORD = db.Column(db.Integer)
    LAST_UPDATE_DTTM = db.Column(db.String(50))
    LAST_UPDATE_INITIALS = db.Column(db.String(18))

    def __repr__(self):
        return '<MAG_BAG {0}>'.format(self.BAG_NM)


#
# 5. Routes & Errors
#
@lm.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(login_id=form.login_id.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash('Login failed. Please try again.')
            return redirect(url_for('login', **request.args))
        login_user(user, form.remember_me.data)
        user.last_seen_dttm = datetime.now()
        db.session.add(user)
        db.session.commit()
        return redirect(request.args.get('next') or url_for('index'))       
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# INDEX
@app.route('/')
@login_required
def index():
    """Each user gets a custom landing page.
    There is no part of the site intended to be used by the public."""
    u = User.query.filter_by(id=current_user.get_id()).first()
    # ToDo query for all entities associated with user
    e_list = Entity.query.filter_by(user_id=current_user.get_id()).all()
    return render_template('index.html', username=u.login_id, entities=e_list)

## DS Table Pages

# DS_MAG_BAG
@app.route('/DS_MAG_BAG', methods=['GET', 'POST'])
@login_required
def DS_MAG_BAG():
    """DS Page for test_setup"""
    errmess = None
    e = Entity.query.filter_by(ds_table_nm='DS_MAG_BAG').first()
    #
    if e.user_id != int(current_user.get_id()):
        abort(403) # forbidden except to specific users

    # executes when user submits
    if request.method == 'POST':
        d = request.form.to_dict()
        # errmess = str( dir(request.form))
        # errmess = str( dir(current_user))

        mb = MAG_BAG.query.filter_by(BAG_ABBREV=d.get('BAG_ABBREV')).first()
        mb.MAGIC_POWER_DESCR = d.get('MAGIC_POWER_DESCR')
        mb.SORT_ORD = int(d.get('SORT_ORD'))
        # audit fields
        mb.LAST_UPDATE_DTTM = datetime.now()
        mb.LAST_UPDATE_INITIALS = current_user.login_id
        # finally update DS table
        db.session.add(mb)
        db.session.commit()
    #
    bags = MAG_BAG.query.all()
    #
    return render_template('DS_MAG_BAG.html', rows=bags, errmess=errmess)


# Errors

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html')

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html')

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html')


#
# 6. Helper Functions
#
def make_shell_context():
    return dict(app=app, db=db, User=User, Entity=Entity,
        test_setup=test_setup, MAG_BAG=MAG_BAG)

def test_setup():
    """Only used during development or testing as a convenience."""
    db.create_all()
    if User.query.filter_by(login_id='felix').first() is None:
        felix = User.register('felix', 'cat')
        user2 = User.register('usr2', 'dog')
        e = Entity.register('Magic Bag', 'DS_MAG_BAG', felix.id)


#
# 7. Run
#
if __name__ == '__main__':
    manager.add_command("shell", Shell(make_context=make_shell_context))
    manager.run()

