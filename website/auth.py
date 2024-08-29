import re
from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from .models import User
from datetime import datetime, timedelta

auth = Blueprint('auth', __name__)

MAX_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=15)  #lockout time - 15 minutes

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        
        user = User.objects(email=email).first()
        if user:
            # Check if the user is locked out
            if user.failed_login_attempts >= MAX_ATTEMPTS:
                if user.last_failed_login and datetime.utcnow() - user.last_failed_login < LOCKOUT_TIME:
                    remaining_lockout = LOCKOUT_TIME - (datetime.utcnow() - user.last_failed_login)
                    flash(f'Account is locked. Try again in {int(remaining_lockout.total_seconds() // 60)} minutes.', category='error')
                    return render_template("./Auth/login.html", user=current_user, email=email)

                # Reset the attempts if the lockout period has passed
                user.failed_login_attempts = 0
                user.last_failed_login = None
                user.save()

            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                # Reset failed attempts after successful login
                user.failed_login_attempts = 0
                user.last_failed_login = None
                user.save()
                return redirect(url_for('views.dashboard'))
            else:
                user.failed_login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                user.save()

                attempts_left = MAX_ATTEMPTS - user.failed_login_attempts
                if attempts_left > 0:
                    flash(f'Incorrect password. You have {attempts_left} attempts left.', category='error')
                else:
                    flash('Account is locked due to too many failed login attempts. Try again later.', category='error')
        else:
            flash('Email does not exist.', category='error')

        # Pass the email back to the form in case of failure
        return render_template("./Auth/login.html", user=current_user, email=email)

    return render_template("./Auth/login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        role = request.form.get('role')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Regular expression for a strong password
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{7,}$'
        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        
        user = User.objects(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif not re.match(email_regex, email):
            flash('Invalid email format', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif not re.match(password_regex, password1):
            flash('Password must be at least 7 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.', category='error')
        else:
            new_user = User(
                email=email,
                role=role,
                first_name=first_name,
                password=generate_password_hash(password1)
            )
            new_user.save()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.dashboard'))

    return render_template("./Auth/sign_up.html", user=current_user)
