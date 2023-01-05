from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Identity
from datetime import datetime
from sqlalchemy.sql import func
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required, user_accessed
from werkzeug.security import check_password_hash, generate_password_hash
#from werkzeug.routing import BaseConverter
from flask_wtf import FlaskForm
from wtforms import (StringField, TextAreaField, IntegerField, BooleanField, SelectField,  RadioField, PasswordField)
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo, Optional, Email

#from app import User
import re

app = Flask(__name__)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"


#db = SQLAlchemy(app)
migrate = Migrate(app)
bcrypt = Bcrypt(app)

#..........................Database 

app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#............flask log in

app.secret_key = 'secret-key'

#--------------------------------Table User-----------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    pwd = db.Column(db.String(72), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    #One to many relationship
    reviews = db.relationship('Review', backref="user", lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'
    
#--------------------------------Table Review--------------------------------------------------------
        
class Review(db.Model):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True)
    eircode= db.Column(db.String(7), nullable=False)
    text= db.Column(db.String(500), nullable=False)
    rating= db.Column(db.String(30), nullable=False)
    time = db.Column(db.DateTime, default=datetime.utcnow)
    #rating= db.Column(db.Integer, nullable=False)
    #Foreing key
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))



 
    def __repr__(self):
        #return f'<Review {self.id}>'
        return f'<Review {self.id}>'

    @property
    def user(self):
        return User.query.filter_by(id=self.user_id).first()

#from app import User, Review

#------------ Forms


class register_form(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(3, 20, message="Please provide a valid name, more than 3 and less than 20 characters.") ]
    )
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    pwd = PasswordField(validators=[InputRequired(), Length(8, 72)])
    cpwd = PasswordField(
        validators=[
            InputRequired(),
            Length(8, 72),
            EqualTo("pwd", message="Type that again, passwords must match."),
        ]
    )


    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Try to log in, email already registered")


class login_form(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 160)])
    pwd = PasswordField(validators=[InputRequired(), Length(min=8, max=72)])
    username = StringField(validators=[Optional()])

#---------------------------------------Reviews Form--------------------------------------------------
class review_form(FlaskForm):
    eircode = StringField(validators=[InputRequired(), Length(7, 7)])
    text = TextAreaField(validators=[InputRequired(),Length(20, 500, message="Please provide at least 20 characters of review and up to 500."),])
    rating = RadioField(validators=[InputRequired()], choices = [('Awesome'),('Pretty Good'),('Ok'),('Made me cry')])
    user_id = RadioField(validators=[InputRequired()], choices = [(login_manager._user_callback),('Anonymous')])

class myreview_form(FlaskForm):
    eircode = StringField(validators=[InputRequired(), Length(7, 7)])
    text = TextAreaField(validators=[InputRequired(),Length(20, 500, message="Please provide at least 20 characters of review and up to 500."),])
    rating = RadioField(validators=[InputRequired()], choices = [('Awesome'),('Pretty Good'),('Ok'),('Made me cry')])
    user_id = RadioField(validators=[InputRequired()], choices = [(current_user),('Anonymous')])

#------------------------------------Search Form----------------------------------------------
class search_form(FlaskForm):
    eircode = StringField(validators=[Length(7, 7)])
    




#--------------Routes- Log in/ Register--------------------


#This keeps the current user object loaded in that current session based on the stored id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


 #------------------------------Route Home---------------------------------------
@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def index():
    form = search_form()
    if form.validate_on_submit():
        try:
            eircode = form.eircode.data
            if eircode != "":
                form.eircode.data= ""
                return render_template('index.html', form=form, reviews = Review.query.filter_by(eircode=eircode).all(), title ="Home")
                

            else: 
                return render_template('index.html', form=form, reviews = Review.query.all() , title ="Home")
        except Exception as e:
            flash(e, "danger")
    #review = Review.query.all()
    #reviews=Review.query.order_by(Review.id).all()
    #    if request.method == "GET":
    
    return render_template('index.html', form=form, reviews = Review.query.all() , title ="Home")
    #return render_template("index.html",title="Home")

#---------------------------Route My Reviews---------------------------------------------
@app.route("/myreviews", methods=("GET", "POST"), strict_slashes=False)
@login_required
def myreviews():
    form = myreview_form()
    user_id = current_user.username
    
    return render_template('myreviews.html', form=form, reviews = Review.query.filter_by(user_id= user_id).all())


# Login route
@app.route("/login", methods=("GET", "POST"), strict_slashes=False)
def login():
    form = login_form()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            #hashpwd = bcrypt.generate_password_hash(form.pwd.data).decode("utf-8")
            #email = request.form['email'] pwd = request.form['pwd'] hashPassword = bcrypt.generate_password_hash(password)
            #formpwd=bcrypt.generate_password_hash(form.pwd.data)
            #if check_password_hash(user.pwd, formpwd):
            #if bcrypt.check_password_hash(user.pwd, hashpwd):
            if bcrypt.check_password_hash(user.pwd, form.pwd.data):
                login_user(user)
                
                return redirect(url_for('index'))
            else:
                flash(f"{form.pwd.data}, {user}, {user.pwd}, Invalid Username or password!", "danger")
        except Exception as e:
            flash(e, "danger")
    return render_template("account.html",form=form)

#Log out
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    
# Register route
@app.route("/account", methods=("GET", "POST"), strict_slashes=False)
def register():
    form = register_form()

    if form.validate_on_submit():
        try:
            email = form.email.data
            pwd = bcrypt.generate_password_hash(form.pwd.data).decode("utf-8")
            username = form.username.data
            
            newuser = User(
                username=username,
                email=email,
                pwd=pwd,
                #pwd=bcrypt.generate_password_hash(pwd),
            )
    
            db.session.add(newuser)
            db.session.commit()
            flash( f"{username}, {pwd}, you are now registered, it's time to log in below", "success")
            
            return redirect(url_for("login"))

        except Exception as e:
            flash(e, "danger")

    return render_template("account.html",form=form)
 

#------------------Post a Review--------------------------------------------------------

@app.route("/post_review", methods=("GET", "POST"), strict_slashes=False)
@login_required
def post_review():
    form = review_form()
    if form.validate_on_submit():
        try:
            text = form.text.data
            eircode = form.eircode.data
            rating = form.rating.data
            user_id = form.user_id.data
            
            newreview = Review(
                text=text,
                eircode=eircode,
                rating = rating,
                user_id= user_id
                
                
             )
    
            db.session.add(newreview)
            db.session.commit()

            return redirect(url_for('index'))

        except Exception as e:
            flash(e, "danger")

    return render_template("post_review.html",form=form)








if __name__ == "__main__":
    app.run(debug=True)
    TEMPLATES_AUTO_RELOAD=True
else:
    gunicorn_app = create_app()



       
#@app.route('/login', methods=['POST','GET'])
#def userlogin():
 #   return render_template('login.html')




#@app.route('/modal', methods=['POST','GET'])
#def modal():
#    return render_template('modal.html')





#@app.route('/about', methods=['POST','GET'])
#@oidc.require_login
#def about():
#    return render_template('about.html')


#@app.route('/call_modal', methods=['GET', 'POST'])
#def call_modal():
#    redirect(url_for('index') + '#myBtn')
