import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    xp = db.Column(db.Integer, default=0)  # Track user XP

    @property
    def level(self):
        return self.xp // 30  # Level up every 30 XP

# Ensure the database and tables are created before handling any request
@app.before_request
def create_tables():
    if not os.path.exists('users.db'):
        db.create_all()

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        user = User.query.filter_by(username=username, password=hashed_password).first()
        if user:
            session['user'] = username
            session['xp'] = user.xp
            flash(f'Hello, {username}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your credentials.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':  # Corrected this line
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash_password(password)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'danger')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('xp', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # Implement your password recovery logic here
        flash('Password recovery instructions sent to your email.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/math')
def math():
    return render_template('math.html')

@app.route('/physics')
def physics():
    return render_template('physics.html')

@app.route('/cs')
def cs():
    return render_template('cs.html')

# Quiz routes
@app.route('/math_quiz')
def math_quiz():
    # Implement your quiz logic here
    return render_template('math_quiz.html')

@app.route('/physics_quiz')
def physics_quiz():
    # Implement your quiz logic here
    return render_template('physics_quiz.html')

@app.route('/cs_quiz')
def cs_quiz():
    # Implement your quiz logic here
    return render_template('cs_quiz.html')

# Route to handle XP gain
@app.route('/earn_xp/<int:xp_amount>', methods=['GET', 'POST'])
def earn_xp(xp_amount):
    if request.method == 'POST':
        # Handle the quiz form submission and add XP if answers are correct
        if 'user' in session:
            user = User.query.filter_by(username=session['user']).first()
            if user:
                # Add XP to the user
                user.xp += xp_amount
                db.session.commit()
                session['xp'] = user.xp
                flash(f'You earned {xp_amount} XP! Current XP: {user.xp}.', 'success')
            else:
                flash('User not found.', 'danger')
        else:
            flash('You need to be logged in to earn XP.', 'danger')
        return redirect(url_for('home'))
    else:
        return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
