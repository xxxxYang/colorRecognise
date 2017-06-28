from flask import render_template, redirect, request, url_for
from flask_login import login_user, login_required, logout_user, current_user
from .. import db
from . import auth
from ..email import send_email
from ..models import User
from .forms import LoginForm, RegistrationForm, PasswordResetRequestForm, \
        PasswordResetForm, ChangePasswordForm


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        auth_key = request.form.get('auth_key', None)
        # print 'email:' + auth_key
        password = request.form.get('password', None)
        user = User.query.filter_by(email=auth_key).first()
        # print 'password:' + password
        if user is not None and user.verify_password(password):
            login_user(user)
            return redirect(request.args.get('next') or url_for('main.index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', None)
        # print 'email:' + email
        password = request.form.get('password', None)
        # print 'password:' + password
        user = User(email=email,
                    username=email,
                    password=password)
        db.session.add(user)
        return redirect(url_for('auth.login'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.email.data,
                    password=form.password.data)
        db.session.add(user)
        return redirect(url_for('auth.login'))
    return render_template('auth/signup.html', form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
            return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            return redirect(url_for('main.index'))
    return render_template("auth/change_password.html", form=form)
