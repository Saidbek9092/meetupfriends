from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import login_user, current_user, logout_user, login_required, LoginManager, UserMixin
from flask_uploads import UploadSet, configure_uploads, ALL
from flask_bootstrap import Bootstrap


app = Flask(__name__)
app.config['SECRET_KEY'] = 'b407c1bbf047582ddasdcbb97344e'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meeting.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Bootstrap(app)
login_manager = LoginManager(app)
files = UploadSet('files', ALL)
app.config['UPLOADS_DEFAULT_DEST'] = 'static'
configure_uploads(app, files)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    meetings = db.relationship('Meeting', backref='author', lazy=True)

    def __repr__(self):
        return 'User ({},{}!)'.format(self.username, self.email)

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String, nullable=False)
    date = db.Column(db.Text, nullable=False)
    time = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return 'Meeting ({}, {}!)'.format(self.subject, self.date_posted)

class Current_Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    meeting_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer, nullable=False)

class FileContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300))
    path = db.Column(db.String)
    user_id = db.Column(db.String, nullable=False)

from forms import LoginForm, RegistrationForm, MeetingForm

@app.before_first_request
def create_db():
    db.create_all()

@app.route('/meetings')
def meetings():
    if current_user.is_authenticated:
        meetings = Meeting.query.all()
        def filter_users(meeting):
            count = Current_Meeting.query.filter_by(meeting_id=meeting.id).count()
            setattr(meeting, 'users_count', count)
            is_joined = Current_Meeting.query.filter_by(meeting_id=meeting.id, user_id=current_user.id).count()
            setattr(meeting, 'is_joined', is_joined)
            print is_joined
            return meeting
        meetings = map(lambda meeting: filter_users(meeting), meetings)
        return render_template('meetings.html', meetings=meetings)
    else:
        return redirect('/')

@app.route('/')


# At the beginning of the project I named project as MeetUpFriends. Later we decided to give name of the website as YUC. So
# here I did not change meetugfriends to the YUC.
def meetupfriends():
    return render_template('meetupfriends.html')

@app.route('/materials')
def materials():
    if current_user.is_authenticated:
        files = FileContent.query.all()
        return render_template('materials.html', files=files)
    else:
        return redirect('/')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['inputFile']
    filename = files.save(file)
    newFile = FileContent(name=file.filename, path=filename, user_id=current_user.username)
    if request.files['inputFile'].filename == '':
        flash('No file uploaded!', 'danger')
        return redirect(url_for('materials'))
    else:
        db.session.add(newFile)
        db.session.commit()
    flash('You material is added!', 'success')
    return redirect(url_for('materials'))

@app.route('/download/<int:file_id>')
def d1(file_id):
    file_data = FileContent.query.filter_by(id=file_id).first()
    return send_file(filename_or_fp='static/files/' + file_data.path, as_attachment=True)

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect('/')
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect('/')
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect('/')
        else:
            flash('Login unsuccessfull! Please check your email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/meeting/new_meeting", methods=['GET', 'POST'])
@login_required
def new_meeting():
    form = MeetingForm()
    if form.validate_on_submit():
        meeting = Meeting(subject=form.subject.data, description=form.description.data, location=form.location.data,
                          date=form.date.data, time=form.time.data, author=current_user)
        db.session.add(meeting)
        db.session.commit()
        flash('Your meeting has been created!', 'success')
        return redirect(url_for('meetings'))
    return render_template('new_meeting.html', title='New Meeting', form=form, legend='New Meeting')


@app.route('/logout')
def logout():
    logout_user()
    return redirect ('/')

@app.route('/account')
@login_required
def account():
    meetings = Meeting.query.filter_by(author=current_user)
    print meetings
    return render_template('account.html', title='Account', meetings=meetings)

@app.route("/meeting/<int:meeting_id>")
def meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    return render_template('meeting.html', subject=meeting.subject, meeting=meeting)

@app.route("/meeting/<int:meeting_id>/update", methods=['GET', 'POST'])
@login_required
def update_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author == current_user or current_user.email == "admin@gmail.com":
        form = MeetingForm()
        if form.validate_on_submit():
            meeting.subject = form.subject.data
            meeting.description = form.description.data
            meeting.location = form.location.data
            meeting.date = form.date.data
            meeting.time = form.time.data
            db.session.commit()
            flash('Your meeting has been updated!', 'success')
            return redirect(url_for('meeting', meeting_id=meeting_id))
        elif request.method == 'GET':
            form.subject.data = meeting.subject
            form.description.data = meeting.description
            form.location.data = meeting.location
            form.date.data = meeting.date
            form.time.data = meeting.time
        return render_template('new_meeting.html', title='Update meeting', form=form, legend='Update Meeting')
    else:
        abort(403)

@app.route("/meeting/<int:meeting_id>/delete", methods=['GET'])
@login_required
def delete_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author == current_user or current_user.email == "admin@gmail.com":
        db.session.delete(meeting)
        db.session.commit()
        flash('Your meeting has been deleted!', 'danger')
        return redirect(url_for('meetings'))
    else:
        abort(403)

@app.route('/add_meeting/<int:meeting_id>')
@login_required
def addMetting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    current_meetings = Current_Meeting.query.all()
    if meeting.author == current_user:
        abort(403)
        return redirect(url_for('meetings'))
    total = 0
    for current_meeting in current_meetings:
        if meeting.id == current_meeting.meeting_id and current_user.id == current_meeting.user_id:
            abort(403)
    cm = Current_Meeting(meeting_id=meeting_id, user_id=current_user.id)
    print total
    db.session.add(cm)
    db.session.commit()
    flash('You joined meeting succesfully!', 'success')
    return redirect(url_for('meetings'))

@app.route('/user/<string:username>')
def user_meetings(username):
    user = User.query.filter_by(username=username).first_or_404()
    meetings = Meeting.query.filter_by(author=user)
    return render_template('user_meetings.html', meetings=meetings, user=user)

if __name__ == '__main__':
    app.run()
