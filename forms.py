from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField, TextAreaField, BooleanField, DateField, DateTimeField
from wtforms.validators import DataRequired, ValidationError, Length, Email,EqualTo
from app import User


class RegistrationForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(Length), Length(min=4, max=20)])
    email = StringField('Email',validators=[DataRequired(Length), Email()])
    password = PasswordField('Password', validators=[DataRequired(),Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username (self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose another one')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already taken. Please choose another one')


class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(Length), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class MeetingForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    date =StringField('Date', validators=[DataRequired()])
    time = StringField('Time', validators=[DataRequired()])
    submit = SubmitField('Submit')



