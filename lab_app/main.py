from flask import Flask, render_template, request, flash
from flask_login._compat import unicode
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, Form
from wtforms.validators import InputRequired, Length, EqualTo, DataRequired
from wtforms.fields.html5 import EmailField
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
import os
import sqlite3
from sqlite3 import Error

currentlocation = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password
        self.authenticated = False


    def is_active(self):
        return self.is_active()

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def get_id(self):
        return self.id


def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn


class RegistrationForm(Form):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "User Name"})
    firstname = StringField('firstname', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "First Name"})
    lastname = StringField('lastname', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Last Name"})
    emailaddress = EmailField('email', validators=[DataRequired(), EqualTo('retype_emailaddress',
                                                                           message='Email must match')],
                              render_kw={"placeholder": "Email Address"})
    retype_emailaddress = EmailField('retypeemail', validators=[DataRequired()], render_kw={"placeholder": "Retype Email Address"})
    password = PasswordField('password', validators=[DataRequired(), Length(min=6, max=20), EqualTo('retype_password',
                                                                                                    message='Password missmatched, need to be similar')], render_kw={"placeholder": "Password"})
    retype_password = PasswordField('Retypepassword', validators=[DataRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Retype Password"})


class LoginForm(Form):
    username = StringField('username', validators=[InputRequired(),
                                                   Length(min=4, max=20)], render_kw={"placeholder": "User Name"})
    emailaddress = EmailField('email', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email Address"})
    password = PasswordField('password', validators=[DataRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Password"})


@login_manager.user_loader
def load_user(user_id):
   conn = create_connection(os.path.join(currentlocation, 'userdb.db'))
   curs = conn.cursor()
   curs.execute("SELECT USERNAME, EMAIL, PASSWORD FROM USERS where USERNAME=?", (user_id,))
   lu = curs.fetchone()
   if lu is None:
      return None
   else:
      return User(lu[0], lu[1], lu[2])


@app.route('/extra', methods=['GET', 'POST'])
def extra():
    return render_template("lab_env_db.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        username = request.form['username']
        conn = create_connection(os.path.join(currentlocation, 'userdb.db'))
        c = conn.cursor()
        c.execute("SELECT USERNAME, EMAIL, PASSWORD FROM USERS where USERNAME=?", (username,))
        entry = c.fetchone()
        entry_username = entry[0]
        entry_emailaddress = entry[1]

        if entry_username:
            formemailaddress = request.form['emailaddress']
            if entry_emailaddress == formemailaddress:
                entry_password = entry[2]
                formpassword = request.form['password']
                if check_password_hash(entry_password, formpassword):
                    return render_template('mainpage.html')
                else:
                    flash("Wrong password .. please check", "info")
            else:
                flash("Your emailaddress hasn't registered.. Please register to the system", "info")
        else:
            flash("Your Username hasn't registered.. Have you registered to the system? Please register", "info")
    return render_template("login.html", form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm(request.form)
    if request.method == "POST" and form.validate():
        username = request.form['username']
        conn = create_connection(os.path.join(currentlocation, 'userdb.db'))
        c = conn.cursor()
        c.execute("SELECT USERNAME, EMAIL FROM USERS where USERNAME=?", (username,))
        row = c.fetchone()
        entry_username = row[0]
        entry_email = row[1]

        if entry_username:
            flash("Your username has already taken.. Choose a new one", "info")
        elif entry_email:
            flash("Your email has already Registered.. Try to login", "info")
        else:
            firstname = request.form['firstname']
            lastname = request.form['lastname']
            emailaddress = request.form['emailaddress']
            password = generate_password_hash(request.form['password'])
            c.execute("INSERT INTO USERS VALUES(?,?,?,?,?)", (username, firstname, lastname, emailaddress, password))
            conn.commit()
            form = LoginForm()
            return render_template('login.html', form=form)
    return render_template("signup.html", form=form)

@app.route('/mainpage')
def mainpage():
    return render_template('mainpage.html')


if __name__ == "__main__":
    app.run(debug=True)
