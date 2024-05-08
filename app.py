from flask import Flask, session, render_template, redirect, url_for, request, flash, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, SearchField
from wtforms.validators import DataRequired
from flask_wtf.file import FileField, FileRequired
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from markupsafe import Markup
import uuid as uuid
import boto3, botocore
import os
from datetime import datetime, timedelta
from wtforms.widgets import TextArea
import re


app = Flask(__name__)
s3 = boto3.client(
    "s3", aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'))
app.config["SECRET_KEY"] = 'qwertyasababyboy'
uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = uri
upload_folder = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = upload_folder
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://lgndcraft:Zainab12@lgndcraft.mysql.pythonanywhere-services.com/lgndcraft$default"
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://avnadmin:AVNS_h_ZG7r7cVTanjOFgI3P@my-flask-db-first-flask-db.b.aivencloud.com:25122/defaultdb"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=60)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


course_tag = db.Table('course_tag',
                      db.Column('id', db.Integer, primary_key=True),
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                      db.Column('course_id', db.Integer, db.ForeignKey('courses.id'))
                      )

course_admins = db.Table('course_admins',
                         db.Column('id', db.Integer, primary_key=True),
                         db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                         db.Column('course_id', db.Integer, db.ForeignKey('courses.id'))
                         )

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    isAdmin = db.Column(db.Boolean, nullable=False)
    dateAdded = db.Column(db.DateTime, default=datetime.utcnow)

    course = db.relationship('Courses', secondary=course_tag, backref='user')
    admin_courses = db.relationship('Courses', secondary=course_admins, backref='admins')
    requester = db.relationship('Requests', backref='requests')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Courses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(100), nullable=False)
    course_description = db.Column(db.Text, nullable=False)
    dateAdded = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign Key Creation
    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    creator = db.relationship('User', backref='created_courses')
    course = db.relationship('Requests', backref='requests_course')
    docs_key = db.relationship("Docs", backref='docs')


# Docs DB
class Docs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    filename_real = db.Column(db.String(100))
    file_size = db.Column(db.Float())
    file_size_str = db.Column(db.String(100))
    dateAdded = db.Column(db.DateTime, default=datetime.utcnow)

    course_id = db.Column(db.Integer, db.ForeignKey("courses.id", name='docs_course_id'))

class Requests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requesting_user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='tch_user'))
    course_id_requested = db.Column(db.Integer, db.ForeignKey('courses.id', name='tch_course'))
    course_owner_id = db.Column(db.Integer())
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'declined'


# Course Creation
class CoursesForm(FlaskForm):
    course_name = StringField("Enter Course Name Here...", validators=[DataRequired()], render_kw={"autocomplete": "off"})
    course_description = StringField("Enter Course Description...", validators=[DataRequired()], render_kw={"autocomplete": "off"}, widget=TextArea())
    submit = SubmitField("Submit")


class Register(FlaskForm):
    name = StringField("Input Fullname Here...", validators=[DataRequired()])
    email = EmailField('Input E-mail Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    password = PasswordField('Input Password Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    confirmPassword = PasswordField('Input Password Again...', validators=[DataRequired()])
    submit = SubmitField("Submit")

class EditProfileName(FlaskForm):
    name = StringField("Input Fullname Here...", validators=[DataRequired()])
    submit = SubmitField("Submit")

class EditProfilePass(FlaskForm):
    currentPassword = PasswordField('Input Old Password Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    newPassword = PasswordField('Input New Password Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    confirmPassword = PasswordField('Input New Password Again...', validators=[DataRequired()])
    submit = SubmitField("Submit")

class Login(FlaskForm):
    email = EmailField('Input E-mail Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    password = PasswordField('Input Password Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    submit = SubmitField("Submit")


class Search(FlaskForm):
    searched = SearchField('Search...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    submit = SubmitField("Submit")


class DocForm(FlaskForm):
    image = FileField('File Here....', validators=[FileRequired()])
    submit = SubmitField('Submit')

@login_required
@app.route("/add_admin/<int:user_id>/<int:course_id>", methods=["GET", "POST"])
def add_admin(course_id, user_id):
    user = current_user
    if user.is_authenticated:
        course = Courses.query.get_or_404(course_id)
        new_admin = User.query.get_or_404(user_id)
        if user == course.creator:
            if new_admin != course.creator:
                if new_admin not in course.admins:
                    try:
                        new_admin.admin_courses.append(course)
                        db.session.commit()
                        flash("Made user admin successfully")
                        return redirect(url_for("courseDashboard", id=course_id))
                    except:
                        flash("An Error Occured")
                        return redirect(url_for("courseDashboard", id=course_id))
                else:
                    flash("You are already an admin of this course")
                    return redirect(url_for("courseDashboard", id=course_id))
            else:
                flash("You can't add yourself again as an admin - You created the course")
                return redirect(url_for(request.referrer))
        else:
            flash("You don't have permission to perform this action")
            return redirect(url_for("dash"))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

@login_required
@app.route("/send_course_request/<int:id>", methods=["GET", "POST"])
def send_course_request(id):
    user = current_user
    if user.is_authenticated:
        course = Courses.query.get_or_404(id)
        if user != course.creator:
            existing_request = Requests.query.filter_by(requesting_user_id=user.id, course_id_requested=course.id, status='pending').first()
            if not existing_request:
                if user not in course.user:
                    if not user.isAdmin:
                        new_request = Requests(requesting_user_id=user.id, course_id_requested=course.id, course_owner_id=course.creator.id)
                        try:
                            db.session.add(new_request)
                            db.session.commit()
                            flash("Request Sent Successfully")
                            return redirect(url_for("dash"))
                        except:
                            flash("Couldn't Send Request")
                    else:
                        flash("You are an instructor, you can't Join a Course")
                        return redirect(request.referrer)
                else:
                    flash("You are already a member of this course")
                    return redirect(url_for("course", id=id))
            else:
                flash("You have already sent a join request for this course")
                return redirect(request.referrer)
        else:
            flash("You cannot send a request for your own course")
            return redirect(url_for("createdCourses"))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

@login_required
@app.route("/courseDashboard/respond_join_request/<int:request_id>/<response>", methods=["GET", "POST"])
def respond_join_request(request_id, response):
    user = current_user
    if user.is_authenticated:
        if user.isAdmin:
            requester = Requests.query.get_or_404(request_id)
            if requester.requests_course.creator != user:
                flash("You are not authorized to respond to this join request")
                return redirect(url_for("dash"))
            if response == "accept":
                try:
                    requester.status = "accepted"
                    requester.requests_course.user.append(requester.requests)
                    db.session.commit()
                    flash("You accepted the Request")
                except:
                    flash("An error Occurred Somewhere")
            elif response == "decline":
                try:
                    requester.status = "declined"
                    db.session.commit()
                    flash("You declined the Request")
                except:
                    flash("An error Occurred Somewhere")
            else:
                flash("Invalid response")
        else:
            flash("You are not authorized to respond to join requests")
        return redirect(request.referrer)
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))
@login_required
@app.route("/add_docs/<int:id>", methods=["GET", "POST"])
def add_docs(id):
    user = current_user
    if user.is_authenticated:
        course = Courses.query.get_or_404(id)
        if user.isAdmin or user == course.creator or user in course.admins:
            if request.method == 'POST':
                file = request.files['file']
                if file:
                    # I really need to start commenting the shit I write and what for

                    # creates the name securely
                    file_filename = secure_filename(file.filename)

                    # adds and encoder or smth like that to the file name
                    file_name = str(uuid.uuid1()) + "_" + file_filename

                    # saves the file
                    bucket_name = os.getenv("AWS_BUCKET_NAME")
                    s3.upload_fileobj(file, bucket_name, file_name)

                    response = s3.head_object(Bucket=bucket_name, Key=file_name)

                    # gets file size in kilobytes
                    file_size = response['ContentLength'] / 1024
                    print(file_size)

                    # saves a str version of it in a column in mi db based on kb and mb
                    if file_size >= 1024:
                        file_size_string = str(round(file_size / 1024, 1)) + "MB"
                    else:
                        file_size_string = str(round(file_size, 1)) + "KB"

                    # uploads document information to the db
                    upload = Docs(filename=file_name, filename_real=file_filename, file_size=file_size, file_size_str=file_size_string, course_id=course.id)
                    try:
                        db.session.add(upload)
                        db.session.commit()
                        flash("Uploaded Successfully")
                    except:
                        flash("Couldn't Upload Document")
                else:
                    flash("Document Required!")
            return render_template("add_docs.html", user=user, course=course)
        else:
            flash("You aren't Permitted to access this page")
            return redirect(url_for('dash'))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

@login_required
@app.route("/delete_doc/<int:id>", methods=["GET", "POST"])
def delete_doc(id):
    user = current_user
    if user.is_authenticated:
        if user.isAdmin:
            docs = Docs.query.get_or_404(id)
            try:
                bucket_name = os.getenv("AWS_BUCKET_NAME")
                s3.delete_object(Bucket=bucket_name, Key=docs.filename)
                try:
                    db.session.delete(docs)
                    db.session.commit()
                    flash("Document deleted Successfully")
                    return redirect(request.referrer)
                except:
                    flash("An error Occurred Somewhere")
            except:
                try:
                    db.session.delete(docs)
                    db.session.commit()
                    flash("An Error Occured - But Records were deleted Successfully")
                    return redirect(request.referrer)
                except:
                    flash("An error Occurred Somewhere")
        else:
            flash("You aren't Permitted to access this page")
            return redirect(url_for('dash'))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))


@login_required
@app.route("/adminpanel", methods=["GET", "POST"])
def adminpanel():
    user = current_user
    if user.is_authenticated:
        if user.isAdmin:
            users = User.query.all()
            courses = Courses.query.all()
            docs = Docs.query.all()
            return render_template("adminPanel.html", user=user, users=users, courses=courses, docs=docs)
        else:
            flash("You are not permitted to access this page")
            return redirect(url_for('dash'))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

@login_required
@app.route("/courseregform", methods=["GET", "POST"])
def registercourse():
    form = CoursesForm()
    user = current_user
    if user.is_authenticated:
        if user.isAdmin:
            poster = current_user.id
        else:
            flash("You aren't Permitted this action")
            return redirect(url_for("dash"))
        name = form.course_name.data
        desc = form.course_description.data
        if form.validate_on_submit():
            new_course = Courses(course_name=name, course_description=desc, creator_id=poster)
            form.course_name.data = ""
            form.course_description.data = ""
            try:
                db.session.add(new_course)
                db.session.commit()
                flash("Course Created Successfully")
                return redirect(url_for('dash'))
            except:
                flash("Sorry, An Error cos of db Occurred")
        return render_template("registercourse.html", form=form, user=user)
    else:
        flash("Your Session Timed Out")
        return redirect(url_for("login"))


@app.route("/")
def land():
    return render_template("index.html")


@login_required
@app.route("/courseDashboard/<int:id>")
def courseDashboard(id):
    user = current_user
    if user.is_authenticated:
        course = Courses.query.get_or_404(id)
        if user.isAdmin or user.id == course.creator.id or user in course.admins:
            docs = Docs.query.filter_by(course_id=id).all()
            docs_len = Docs.query.filter_by(course_id=id).count()
            requests = Requests.query.filter_by(status='pending', course_id_requested=course.id).all()
            requests_len = Requests.query.filter_by(status='pending', course_id_requested=course.id).count()

            users = course.user
            user_len = len(course.user)
        else:
            flash("You aren't granted this permission")
            return redirect(url_for("dash"))
    else:
        flash("Session has expired")
        return redirect(url_for('login'))


    return render_template("courseDashboard.html", user=user, course=course, docs=docs, requests_len=requests_len, docs_len=docs_len, user_len=user_len, users=users, requests=requests)




@app.route('/login', methods=["GET", "POST"])
def login():
    form = Login()
    if not current_user.is_authenticated:
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                if check_password_hash(user.password_hash, form.password.data):
                    login_user(user)
                    return redirect(url_for('dash'))
                else:
                    flash("Password is Incorrect")
            else:
                flash(Markup("Account not Found. <a href='register'>Create One?</a>"))
        return render_template("login.html", form=form)
    else:
        return redirect(url_for('dash'))


@app.context_processor
def smth():
    form = Search()
    user = current_user
    if user.is_authenticated:
        request = Requests.query.filter_by(course_owner_id=user.id, status='pending').count()
        return dict(form=form, request=request)
    else:
        return dict(form=form)


@login_required
@app.route('/search', methods=["POST"])
def search():
    form = Search()
    if current_user.is_authenticated:
        user = current_user
        if form.validate_on_submit():
            post = form.searched.data
            post = post.lower()
            courses = Courses.query.filter(Courses.course_name.lower().like('%' + post + '%'))
            courses = courses.order_by(Courses.course_name).all()
            return render_template("search.html", form=form, user=user, searched=post.lower(), courses=courses)
    else:
        flash("Your Session Timed Out")
        return redirect(url_for("login"))

@login_required
@app.route('/member_course/<int:id>')
def course(id):
    courses = Courses.query.get_or_404(id)
    user = current_user
    docs = Docs.query.filter_by(course_id=id).all()
    if user.is_authenticated:
        if courses in user.course or user.isAdmin:
            id = current_user.id
        else:
            flash("You need to have registered this course")
            return redirect(url_for("dash"))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for("login"))
    return render_template('member_course.html', courses=courses, user=user, id=id, docs=docs)

@login_required
@app.route('/unmember_course/<int:id>')
def unmember_course(id):
    courses = Courses.query.get_or_404(id)
    user = current_user
    if user.is_authenticated:
        id = current_user.id
    else:
        flash("Your Session Timed Out")
        return redirect(url_for("login"))
    return render_template('unmember_course.html', courses=courses, user=user, id=id)


@login_required
@app.route('/courses', methods=["GET", "POST"])
def courses():
    courses_ = Courses.query.order_by(Courses.dateAdded)
    if current_user.is_authenticated:
        user = current_user
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

    return render_template("courses.html", user=user, courses=courses_)



@login_required
@app.route('/myCourses', methods=["GET", "POST"])
def myCourses():
    user = current_user
    if user.is_authenticated:
        my_course = user.course
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

    return render_template("myCourses.html", user=user, my_course=my_course)

@login_required
@app.route('/createdCourses', methods=["GET", "POST"])
def createdCourses():
    user = current_user
    if user.is_authenticated:
        if user.isAdmin:
            # requests = Requests.query.filter_by(course_owner_id=user.id, status='pending').all()
            user_courses = Courses.query.filter_by(creator_id=user.id).all()
            course_pending_requests = []
            for course in user_courses:
                pending_request_count = Requests.query.filter_by(course_id_requested=course.id, status='pending').count()
                course_pending_requests.append((course, pending_request_count))
            sorted_courses = sorted(course_pending_requests, key=lambda x: x[1], reverse=True)
        else:
            flash("You Can't Access this Page")
            return redirect(url_for('dash'))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))
    return render_template("CreatedCourses.html", user=user, course=sorted_courses)

@login_required
@app.route('/download/<int:id>')
def download(id):
    if current_user.is_authenticated:
        upload = Docs.query.filter_by(id=id).first()
        if upload is not None:
            # location = app.config['UPLOAD_FOLDER'] + upload.filename
            bucket_name = os.getenv("AWS_BUCKET_NAME")
            try:
                response = s3.get_object(Bucket=bucket_name, Key=upload.filename)
                return send_file(response['Body'], download_name=upload.filename_real, as_attachment=True)
            except FileNotFoundError as e:
                flash("The Document was not found, It probably has been deleted from the server")
                return redirect(request.referrer)
            except:
                flash("There was an issue establishing connection")
                return redirect(request.referrer)
        else:
            flash("File not found... It was probably deleted")
            return redirect(request.referrer)
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))


@login_required
@app.route("/removeCourse/<int:id>", methods=["GET", "POST"])
def removeCourse(id):
    user = current_user
    course = Courses.query.get_or_404(id)
    if user.is_authenticated:
        p = user
        try:
            p.course.remove(course)
            db.session.commit()
            flash("Course Removed Successfully - " + course.course_name)
            return redirect(url_for("dash"))
        except:
            flash("Couldn't Remove - " + course.course_name)
            return redirect(url_for("dash"))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

@login_required
@app.route("/removeUser/<int:id>/<int:uid>", methods=["GET", "POST"])
def removeUser(id, uid):
    user = current_user
    inn_user = User.query.get_or_404(uid)
    course = Courses.query.get_or_404(id)
    if user.is_authenticated:
        p = inn_user
        try:
            p.course.remove(course)
            db.session.commit()
            flash("User Removed Successfully from - " + course.course_name)
            return redirect(url_for('courseDashboard', id=course.id))
        except:
            flash("Couldn't Remove " + inn_user + " From " + course.course_name)
            return redirect(url_for('courseDashboard', id=course.id))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))

@login_required
@app.route('/edit/<int:id>', methods=["GET", "POST"])
def edit_course(id):
    if current_user.is_authenticated:
        courses = Courses.query.get_or_404(id)
        form = CoursesForm()
        user = current_user
        if form.validate_on_submit():
            courses.course_name = form.course_name.data
            courses.course_description = form.course_description.data
            try:
                db.session.commit()
                flash("Course has been updated")
                return redirect(url_for("courseDashboard", id=courses.id))
            except:
                flash("Sorry, An Error cos of db Occurred")
        if user.id == courses.creator.id:
            form.course_name.data = courses.course_name
            form.course_description.data = courses.course_description
            return render_template('edit_course.html', form=form, user=user)
        else:
            flash("You can't perform this action")
            return redirect(request.referrer)
    else:
        flash("Your Session Timed Out")
        return redirect(url_for("login"))


@login_required
@app.route('/delete_course/<int:id>')
def delete_course(id):
    course_to_delete = Courses.query.get_or_404(id)
    user = current_user
    if user.is_authenticated:
        id = current_user.id
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))
    if id == course_to_delete.creator.id:
        try:
            course_to_delete.user.clear()
            db.session.commit()
        except:
            flash("There was an error deleting this course, Try Again")
            return redirect(url_for(request.referrer))
        else:
            db.session.delete(course_to_delete)
            db.session.commit()
            flash("Course was Deleted")
            return redirect(url_for('courses'))
    else:
        flash("You can't delete this course - You aren't the creator")
        courses = Courses.query.order_by(Courses.dateAdded)
        return render_template("courses.html", user=user, courses=courses)


@login_required
@app.route('/dashboard')
def dash():
    courses = Courses.query.order_by(Courses.dateAdded)
    if current_user.is_authenticated:
        user = current_user
        cou = len(user.course)
        ccou = Courses.query.filter_by(creator_id=user.id).count()
        print(user.admin_courses)
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))
    return render_template("dashboard.html", user=user, courses=courses, cou=cou, ccou=ccou)


@app.route('/register', methods=["GET", "POST"])
def register():
    name = None
    email = None
    statte = 2
    form = Register()
    # Validating Form
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        confPassword = form.confirmPassword.data
        pass_len = len(password)
        name_len = len(name)
        if name_len > 7:
            if password == confPassword:
                if pass_len > 7:
                    user = User.query.filter_by(email=email).first()
                    if user is None:
                        hashed_pwd = generate_password_hash(password)
                        all_users = User.query.all()
                        all_users_count = len(all_users)
                        if all_users_count == 0:
                            new_user = User(name=name,
                                            email=email,
                                            password_hash=hashed_pwd,
                                            isAdmin=True)
                        else:
                            new_user = User(name=name,
                                            email=email,
                                            password_hash=hashed_pwd,
                                            isAdmin=False)
                        form.name.data = ""
                        form.email.data = ""
                        form.password.data = ""
                        try:
                            db.session.add(new_user)
                            db.session.commit()
                            flash(Markup('Account Creation Successful. <a href="login">Log in</a> here'))
                            statte = 0
                        except:
                            flash("Unexpected Error")
                            statte = 1
                    elif user:
                        flash(Markup('Already Existing E-mail. <a href="login">Log in</a> here or <a href="register">Sign Up</a>'))
                        statte = 1
                    else:
                        flash("Unexpected Error")
                        statte = 1
                else:
                    flash("Password too short, lengthen it a bit more")
                    statte = 1
            else:
                flash("Passwords Must Match!")
                statte = 1
        else:
            flash("Name too short, lengthen it a bit more")
            statte = 1
    return render_template("register.html", name=name, form=form, statte=statte)

@login_required
@app.route("/makeAdmin/<int:id>", methods=["POST", "GET"])
def makeAdmin(id):
    if current_user.is_authenticated:
        users = User.query.get_or_404(id)
        if current_user.isAdmin:
            try:
                users.isAdmin = True
                db.session.commit()
                flash("Successfully Made " + users.name + " an Admin")
            except:
                flash("An Error Occurred")
        else:
            flash("You aren't an Admin")
    else:
        return redirect(url_for('login'))
    return redirect(url_for('adminpanel'))

# @login_required
# @app.route("/removeAdmin/<int:id>", methods=["POST", "GET"])
# def removeAdmin(id):
#     if current_user.is_authenticated:
#         users = User.query.get_or_404(id)
#         if current_user.isAdmin:
#             if users.id == 1:
#                 flash("You can't remove Admin as this is a Super Admin")
#             else:
#                 try:
#                     users.isAdmin = False
#                     db.session.commit()
#                     flash("Successfully Removed " + users.name + " as an Admin")
#                 except:
#                     flash("An Error Occurred")
#         else:
#             flash("You aren't an Admin")
#     else:
#         return redirect(url_for('login'))
#     return redirect(url_for('adminpanel'))

@login_required
@app.route("/edit_profile/<int:id>", methods=["POST", "GET"])
def edit_profile(id):
    if current_user.is_authenticated:
        user_edit = User.query.get_or_404(id)
        form = EditProfileName()
        formp = EditProfilePass()
        user = current_user
        if formp.validate_on_submit():
            password = formp.currentPassword.data
            new_pass_len = len(formp.newPassword.data)
            if new_pass_len > 7:
                if check_password_hash(user_edit.password_hash, password):
                    hashed_pwd = generate_password_hash(formp.newPassword.data)
                    user_edit.password_hash = hashed_pwd
                    try:
                        db.session.commit()
                        flash("Changes have been Made")
                        return redirect(url_for('dash'))
                    except:
                        flash("Sorry, An Error Occurred")
                else:
                    flash("Password isn't Correct")
            else:
                flash("Password is too short")

        if form.validate_on_submit():
            user_edit.name = form.name.data
            try:
                db.session.commit()
                flash("Changes have been Made")
                return redirect(url_for('dash'))
            except:
                flash("Sorry, An Error Occurred")
        if user.id == user_edit.id:
            form.name.data = user_edit.name
            return render_template('edit_profile.html', form=form, user=user, formp=formp)
        else:
            flash("You can't perform this action")
            return redirect(url_for('dash'))
    else:
        flash("Your Session Timed Out")
        return redirect(url_for("login"))

@login_required
@app.route("/delete/<int:id>")
def delete(id):
    if current_user.is_authenticated:
        if current_user.id == 1:
            if id > 1:
                users = User.query.get_or_404(id)
                try:
                    users.course.clear()
                    db.session.commit()
                except:
                    flash("Some Error Occurred, Try Again")
                else:
                    db.session.delete(users)
                    db.session.commit()
                    flash("User was Successfully Deleted")
            else:
                flash("Can't Delete This User")
        else:
            flash("You aren't permitted!")
    else:
        flash("Your Session Timed Out")
        return redirect(url_for('login'))
    return redirect(url_for("adminpanel"))

@login_required
@app.route("/logout")
def log_out():
    logout_user()
    flash("You have been logged out")
    return redirect("login")


@app.errorhandler(404)
def page_not_found(e):
    if current_user.is_authenticated:
        user = current_user
    else:
        return redirect(url_for('login'))
    courses = Courses.query.order_by(Courses.dateAdded)
    return render_template("404.html", user=user, courses=courses)


@app.errorhandler(500)
def page_not_found(e):
    if current_user.is_authenticated:
        user = current_user
    else:
        return redirect(url_for('login'))
    courses = Courses.query.order_by(Courses.dateAdded)
    return render_template("500.html", user=user, courses=courses)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
