from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from functools import wraps
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import argon2
from data import Articles

app = Flask(__name__)

# ! Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# ! Initialise MySQL
mysql = MySQL(app)

Articles = Articles()

# ! Index
@app.route('/')
def index():
    return render_template('index.html')

# ! About
@app.route('/about')
def about():
    return render_template('about.html')

# ! Single Article
@app.route('/articles')
def articles():
    return render_template('articles.html', articles=Articles)


# ! Single Article
@app.route('/article/<string:id>/')
def article(id):
    return render_template('article.html', id=id)

# ! Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')

# ! User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = argon2.hash(str(form.password.data))

        #  Create cursor
        cur = mysql.connection.cursor()
        # Execute query
        cur.execute("INSERT INTO users (name, email, username, password) VALUES (%s, %s, %s, %s)",
                    (name, email, username, password))
        # Commit to DB
        mysql.connection.commit()
        cur.close()
        flash('You are now registered and can log in.', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# ! User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute(
            "SELECT * FROM users WHERE username = %s", [username])
        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password_hash = data['password']
            # Compare passwords
            if argon2.verify(password_candidate, password_hash):
                app.logger.info('PASSWORD MATCHED')
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.info('INVALID PASSWORD')
                error = 'Invalid password.'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            app.logger.info('USERNAME NOT FOUND')
            error = 'Username not found.'
            return render_template('login.html', error=error)
    return render_template('login.html')

# ! Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# ! Check if user logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Unauthorised. Please login', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ! Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.secret_key = 'mysupersecret'
    app.run(debug=True)
