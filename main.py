from flask import Flask, render_template, request, redirect, flash, url_for, Response
from flask_sqlalchemy import SQLAlchemy
from pytz import timezone
from werkzeug.utils import secure_filename
import uuid as uuid
import os
import pymysql
from datetime import datetime
from cryptography.fernet import Fernet
from Function import encrypt, encrypt_password, hash0, hash1, hash2, decrypt, mail
from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Password@localhost/DatabaseName'
UPLOAD_FOLDER = 'cvs/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route(f'/{encrypt("logout")}', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    current_year = datetime.now().year
    flash("You Have Been Logged Out!")
    return redirect(url_for('login', current_year=current_year))


@app.route(f'/{encrypt("dashboard")}', methods=['GET', 'POST'])
@login_required
def dashboard():
    name = decrypt(current_user.name)
    phone = decrypt(current_user.phone)
    gender = decrypt(current_user.gender)
    email = decrypt(current_user.email)
    row = [name, current_user.id, phone, gender, email, current_user.account_type, current_user.date_added]
    return render_template('dashboard.html', data=row)


class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_job_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    requirement = db.Column(db.String(200), nullable=False)
    job_type = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    dob = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(255), nullable=False)
    psw = db.Column(db.String(1000), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))
    account_type = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'


class Blocked(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))


class accepted(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    accepted_user_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    post = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(200), nullable=False)
    experience = db.Column(db.String(200), nullable=False)
    qualification = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(200), nullable=False)
    state = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.String(200), nullable=False)
    pincode = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.String(200), nullable=False)
    pdf_name = db.Column(db.String(255), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    date_applied = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))


class selected(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    accepted_user_id = db.Column(db.Integer, nullable=False)
    selected_user_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    post = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(200), nullable=False)
    experience = db.Column(db.String(200), nullable=False)
    qualification = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(200), nullable=False)
    state = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.String(200), nullable=False)
    pincode = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.String(200), nullable=False)
    pdf_name = db.Column(db.String(255), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    date_applied = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))


class applied(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    post = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(200), nullable=False)
    experience = db.Column(db.String(200), nullable=False)
    qualification = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(200), nullable=False)
    state = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.String(200), nullable=False)
    pincode = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.String(200), nullable=False)
    pdf_name = db.Column(db.String(255), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    date_applied = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))


@app.route("/")
def home():
    current_year = datetime.now().year
    return render_template('index.html', current_year=current_year)


@app.route(f'/{encrypt("user")}', methods=['GET', 'POST'])
@login_required
def user_list():
    current_year = datetime.now().year
    try:
        if current_user.account_type == "Owner":
            data = db.session.query(Users).all()
            row = []
            for user in data:
                name = decrypt(user.name)
                dob = decrypt(user.dob)
                phone = decrypt(user.phone)
                gender = decrypt(user.gender)
                email = decrypt(user.email)
                row.append((user.id, name, gender, dob, user.account_type, email, phone))
            return render_template('user.html', data=row, current_year=current_year)
        else:
            flash("You doesn't have permission to access this page!")
            return redirect(url_for("home", current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("update_user")}/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    current_year = datetime.now().year
    try:
        user = Users.query.get(user_id)
        if request.method == 'POST':
            user.name = encrypt(request.form['name'])
            user.dob = encrypt(request.form['Dob'])
            user.phone = encrypt(request.form['phone'])
            db.session.commit()
            flash('User information updated successfully')
            return redirect(url_for('dashboard', user_id=user.id, current_year=current_year))
        return render_template('update.html', user=user, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("change_psw")}/<int:user_id>', methods=['GET', 'POST'])
def change_psw(user_id):
    current_year = datetime.now().year
    try:
        user = Users.query.get(user_id)
        if request.method == 'POST':
            salt = 'wqPDlMOPw5PChcOkwoHDn8OZw6I='
            Password = hash2(hash1(hash0(encrypt(key="Key", clear=encrypt_password(request.form['psw'] + salt)))))
            if request.form['retype'] == request.form['psw']:
                msg = "Your Password has been updated."
                subject = "Password Changed!"
                mail(decrypt(current_user.email), msg, subject)
                user.psw = encrypt(Password)
                db.session.commit()
                flash('User information updated successfully')
                return redirect(url_for('home', user_id=user.id, current_year=current_year))
            else:
                flash('Both Password not matching!')
                return render_template("change_psw.html", user=user, current_year=current_year)
        return render_template('change_psw.html', user=user, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("forget_Password")}', methods=['GET', 'POST'])
def forget_password():
    current_year = datetime.now().year
    try:
        if request.method == "POST":
            user = Users.query.filter_by(email=encrypt(request.form['email'])).first()
            if user:
                psw = decrypt(user.psw)
                msg = f"You are requested for forget Password. your forget password login password is '{psw}' . " \
                      f"Neglect the first and last single quotes and copy paste the password in forget password login " \
                      f"page. \n It Won't work on normal login page." \
                      f"After Login go to dashboard and change the password."
                sub = "Forget password login password!"
                mail(decrypt(user.email), msg, sub)
                flash("Password has been sent to your mail id.")
                return render_template('forget_login.html', current_year=current_year)
            else:
                flash("User not found.")
                return render_template("forget.html", current_year=current_year)
        else:
            return render_template('forget.html', current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("forget_login")}', methods=['GET', 'POST'])
def forget_login():
    current_year = datetime.now().year
    try:
        if request.method == 'POST':
            email = encrypt(request.form['email'])
            passwo = encrypt(request.form['psw'])
            user = Users.query.filter_by(email=email).first()
            if user:
                psw = Users.query.filter_by(psw=passwo).first()
                if psw:
                    msg = "You had logged in our sites."
                    sub = "Login Detected!!"
                    mail(request.form['email'], msg, sub)
                    login_user(user)
                    flash('Logged in successfully.')
                    return redirect(url_for('home', current_year=current_year))
                else:
                    msg = "Someone is trying to login in our site using your credentials."
                    sub = "Someone is trying to login."
                    mail(request.form['email'], msg, sub)
                    flash("Email or password doesn't matches!")
                    return render_template("forget_login.html", current_year=current_year)
            else:
                flash("User not found!")
                return render_template("forget_login.html", current_year=current_year)
        return render_template('forget_login.html', current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("applied")}', methods=['GET', 'POST'])
@login_required
def applied_form_submission():
    current_year = datetime.now().year
    try:
        file = request.files['pdf']
        name = str(uuid.uuid1()) + "_" + secure_filename(file.filename)
        key = Fernet.generate_key()
        key_str = key.decode('utf-8')
        fernet = Fernet(key_str)
        content = file.read()
        encrypted_content = fernet.encrypt(content)
        if 'name' in request.form and 'jobpost' in request.form and 'Department' in request.form and \
                'Qualification' in request.form and 'Experience' in request.form and 'address' in request.form and \
                'Gender' in request.form and 'state' in request.form and 'Dob' in request.form and \
                'pincode' in request.form and 'email' in request.form and 'phone' in request.form:
            if current_user.email == encrypt(request.form['email']):
                save_pdf(encrypted_content, name)
                msg = "Your Job Application Was submitted Successfully!!!"
                sub = "Job Application submission."
                application = applied(user_id=current_user.id, name=encrypt(request.form['name']),
                                      post=encrypt(request.form['jobpost']),
                                      department=encrypt(request.form['Department']),
                                      qualification=encrypt(request.form['Qualification']),
                                      experience=encrypt(request.form['Experience']),
                                      address=encrypt(request.form['address']),
                                      gender=encrypt(request.form.get('Gender')),
                                      state=encrypt(request.form['state']), dob=encrypt(request.form['Dob']),
                                      pincode=encrypt(request.form['pincode']),
                                      email=encrypt(request.form['email']), phone=encrypt(request.form['phone']),
                                      pdf_name=name, content=key_str)
                db.session.add(application)
                db.session.commit()
                mail(request.form['email'], msg, sub)
                flash("Your Job application was submitted Successfully!")
                return redirect(url_for("applications_display", current_year=current_year))
            else:
                flash("Your Email and the given email doesn't match.")
                return render_template("application.html", current_year=current_year)
        else:
            flash("Fill all the fields!")
            return render_template("application.html", current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("csejobs")}', methods=['GET', 'POST'])
@login_required
def cse_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('CSE')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("itjobs")}', methods=['GET', 'POST'])
@login_required
def it_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('IT')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("ecejobs")}', methods=['GET', 'POST'])
@login_required
def ece_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('ECE')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("aidsjobs")}', methods=['GET', 'POST'])
@login_required
def aids_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('AIDS')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("mechjobs")}', methods=['GET', 'POST'])
@login_required
def mech_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('MECH')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("mbajobs")}', methods=['GET', 'POST'])
@login_required
def mba_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('MBA')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("eeejobs")}', methods=['GET', 'POST'])
@login_required
def eee_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('EEE')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("otherjobs")}', methods=['GET', 'POST'])
@login_required
def other_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('OTHERS')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("civiljobs")}', methods=['GET', 'POST'])
@login_required
def civil_jobs():
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter(Jobs.department == encrypt('CIVIL')).all()
        rows = []
        for job in data:
            title = decrypt(job.title)
            department = decrypt(job.department)
            description = decrypt(job.description)
            requirement = decrypt(job.requirement)
            job_type = decrypt(job.job_type)
            category = decrypt(job.category)
            rows.append((title, department, description, requirement, job_type, category))
        return render_template('applyjobs.html', data=rows, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("apply_job")}', methods=['GET', 'POST'])
@login_required
def apply_job():
    current_year = datetime.now().year
    return render_template("application.html", current_year=current_year)


@app.route('/view_pdf/<name>/<key>')
def view_pdf(name, key):
    fernet = Fernet(key)
    path = os.path.join(app.config['UPLOAD_FOLDER'], name)
    with open(path, 'rb') as f:
        encrypted_content = f.read()
    content = fernet.decrypt(encrypted_content)
    return Response(content, mimetype='application/pdf')


@app.route(f'/{encrypt("applicaton_display")}')
@login_required
def applications_display():
    current_year = datetime.now().year
    try:
        if current_user.account_type == "Owner" or current_user.account_type == "Admin":
            data = db.session.query(applied).all()
            row = []
            for i in data:
                name = decrypt(i.name)
                post = decrypt(i.post)
                dep = decrypt(i.department)
                exp = decrypt(i.experience)
                quali = decrypt(i.qualification)
                gender = decrypt(i.gender)
                dob = decrypt(i.dob)
                email = decrypt(i.email)
                phone = decrypt(i.phone)
                row.append((name, post, dep, exp, quali, gender, dob, email, phone, i.pdf_name, i.id, i.content))
            return render_template('application_list.html', data=row, current_year=current_year)
        else:
            data = db.session.query(applied).filter_by(user_id=current_user.id).all()
            row = []
            for i in data:
                name = decrypt(i.name)
                post = decrypt(i.post)
                dep = decrypt(i.department)
                exp = decrypt(i.experience)
                quali = decrypt(i.qualification)
                gender = decrypt(i.gender)
                dob = decrypt(i.dob)
                email = decrypt(i.email)
                phone = decrypt(i.phone)
                row.append((name, post, dep, exp, quali, gender, dob, email, phone, i.pdf_name, i.id, i.content))
            return render_template('application_list.html', data=row, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/move_to_accepted/<int:id>', methods=['POST'])
@login_required
def move_to_accepted(id):
    current_year = datetime.now().year
    try:
        applied_data = db.session.query(applied).filter_by(id=id).first()
        if applied_data:
            msg = f"Congratulation, Your application was approved for the position of {decrypt(applied_data.post)}" \
                  f". Within three working days, you must attend the college for an interview (time: 10AM–11AM). " \
                  f"Your user id is {applied_data.user_id}."
            sub = "Your application has been approved!"
            mail(decrypt(applied_data.email), msg, sub)

            accepted_data = accepted(accepted_user_id=current_user.id, user_id=applied_data.user_id,
                                     name=applied_data.name,
                                     post=applied_data.post, address=applied_data.address,
                                     department=applied_data.department, experience=applied_data.experience,
                                     qualification=applied_data.qualification, gender=applied_data.gender,
                                     dob=applied_data.dob, pincode=applied_data.pincode, state=applied_data.state,
                                     email=applied_data.email, phone=applied_data.phone, pdf_name=applied_data.pdf_name,
                                     content=applied_data.content)
            db.session.add(accepted_data)
            db.session.delete(applied_data)
            db.session.commit()
            flash("Application has been Accepted!")
        else:
            return render_template("wrong.html", current_year=current_year)

        return redirect(url_for('applications_display', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("accepted_list")}', methods=['GET', 'POST'])
@login_required
def accepted_list():
    current_year = datetime.now().year
    try:
        if current_user.account_type == "Owner" or current_user.account_type == "Admin":
            data = db.session.query(accepted).all()
            row = []
            for i in data:
                name = decrypt(i.name)
                post = decrypt(i.post)
                dep = decrypt(i.department)
                exp = decrypt(i.experience)
                quali = decrypt(i.qualification)
                gender = decrypt(i.gender)
                dob = decrypt(i.dob)
                email = decrypt(i.email)
                phone = decrypt(i.phone)
                row.append((i.user_id, name, post, dep, exp, quali, gender, dob, email, phone, i.pdf_name, i.id,
                            i.content, i.accepted_user_id))
            return render_template('Accepted_list.html', data=row, current_year=current_year)
        else:
            return redirect(url_for('page_not_found', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/data/remove/<int:id>', methods=['POST'])
@login_required
def remove_user(id):
    current_year = datetime.now().year
    try:
        data = db.session.query(accepted).filter_by(id=id).first()
        delete_pdf(data.pdf_name)
        db.session.delete(data)
        db.session.commit()
        return redirect(url_for("accepted_list", current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/move_to_selected/<int:id>', methods=['POST'])
@login_required
def move_to_selected(id):
    current_year = datetime.now().year
    try:
        applied_data = db.session.query(accepted).filter_by(id=id).first()
        if applied_data:
            msg = f"Congratulation, Your are selected as the {decrypt(applied_data.post)}." \
                  f"Your User id is {applied_data.user_id}"
            sub = "Your application has been approved!"
            mail(decrypt(applied_data.email), msg, sub)
            selected_data = selected(accepted_user_id=applied_data.accepted_user_id, selected_user_id=current_user.id,
                                     user_id=applied_data.user_id, name=applied_data.name,
                                     post=applied_data.post, address=applied_data.address,
                                     department=applied_data.department, experience=applied_data.experience,
                                     qualification=applied_data.qualification, gender=applied_data.gender,
                                     dob=applied_data.dob, pincode=applied_data.pincode, state=applied_data.state,
                                     email=applied_data.email, phone=applied_data.phone, pdf_name=applied_data.pdf_name,
                                     content=applied_data.content)
            db.session.add(selected_data)
            db.session.delete(applied_data)
            db.session.commit()

            flash("Application has been Selected!")
        else:
            flash("Application not found or has already been Selected.")

        return redirect(url_for('accepted_list', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/data/reject/<int:id>', methods=['POST'])
@login_required
def reject(id):
    current_year = datetime.now().year
    try:
        data = db.session.query(applied).filter_by(id=id).first()
        msg = f"We regret to inform you that we have rejected your application for the position of " \
              f"{decrypt(data.post)}."
        sub = "Your Application has been Rejected!!"
        delete_pdf(data.pdf_name)
        if current_user.account_type == "Owner" or current_user.account_type == "Admin":
            mail(decrypt(data.email), msg, sub)
            db.session.delete(data)
            db.session.commit()
        else:
            db.session.delete(data)
            db.session.commit()
        return redirect(url_for('applications_display', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/data/remove/<int:id>', methods=['POST'])
@login_required
def remove(id):
    current_year = datetime.now().year
    try:
        data = db.session.query(applied).filter_by(id=id).first()
        delete_pdf(data.pdf_name)
        db.session.delete(data)
        db.session.commit()
        return redirect(url_for('applications_display', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("selected_list")}', methods=['GET', 'POST'])
@login_required
def selected_list():
    current_year = datetime.now().year
    try:
        if current_user.account_type == "Owner" or current_user.account_type == "Admin":
            data = db.session.query(selected).all()
            row = []
            for i in data:
                name = decrypt(i.name)
                post = decrypt(i.post)
                dep = decrypt(i.department)
                exp = decrypt(i.experience)
                quali = decrypt(i.qualification)
                gender = decrypt(i.gender)
                dob = decrypt(i.dob)
                email = decrypt(i.email)
                phone = decrypt(i.phone)
                row.append((i.accepted_user_id, i.selected_user_id, name, post, dep, exp, quali, gender, dob,
                            email, phone, i.pdf_name, i.id, i.content))
            return render_template('selected_list.html', data=row, current_year=current_year)
        else:
            return redirect(url_for('page_not_found', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/data/reject_user/<int:id>', methods=['POST'])
@login_required
def reject_user(id):
    current_year = datetime.now().year
    try:
        data = db.session.query(selected).filter_by(id=id).first()
        delete_pdf(data.pdf_name)
        db.session.delete(data)
        db.session.commit()
        flash("Applicant was removed successfully!")
        return redirect(url_for("selected_list", current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/Jobs')
@login_required
def display_jobs():
    current_year = datetime.now().year
    try:
        if current_user.account_type == "Owner" or current_user.account_type == "Admin":
            jobs = db.session.query(Jobs).all()
            rows = []
            for job in jobs:
                post_job_id = job.post_job_id
                title = decrypt(job.title)
                department = decrypt(job.department)
                description = decrypt(job.description)
                requirement = decrypt(job.requirement)
                job_type = decrypt(job.job_type)
                category = decrypt(job.category)
                id = job.id
                rows.append((post_job_id, title, department, description, requirement, job_type, category, id))
            return render_template('Jobs.html', data=rows, current_year=current_year)
        else:
            return redirect(url_for('page_not_found', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/data/delete/<int:id>', methods=['POST'])
@login_required
def delete_data(id):
    current_year = datetime.now().year
    try:
        data = db.session.query(Jobs).filter_by(id=id).first()
        if current_user.account_type == "Owner" or current_user.id == data.post_job_id:
            db.session.delete(data)
            db.session.commit()
            return redirect(url_for('display_jobs', current_year=current_year))
        else:
            flash("You are Allowed to Perform this action...")
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/post_job', methods=['GET', 'POST'])
@login_required
def post_job():
    current_year = datetime.now().year
    try:
        if request.method == 'POST':

            if 'job-title' in request.form and 'Department' in request.form and 'job-description' in request.form and \
                    'job-requirements' in request.form and 'job-type' in request.form and \
                    'job-category' in request.form:
                Job = Jobs(title=encrypt(request.form['job-title']), post_job_id=current_user.id,
                           department=encrypt(request.form.get('Department')),
                           description=encrypt(request.form['job-description']),
                           requirement=encrypt(request.form['job-requirements']),
                           job_type=encrypt(request.form.get('job-type')),
                           category=encrypt(request.form.get('job-category')))
                db.session.add(Job)
                db.session.commit()
                flash("Job was posted successfully!")
                return redirect(url_for("display_jobs", current_year=current_year))
            else:
                flash("Fill all the Field!")
                return render_template("jobpost.html", current_year=current_year)
        else:
            if current_user.account_type == "Owner" or current_user.account_type == "Admin":
                return render_template('jobpost.html', current_year=current_year)
            else:
                return redirect(url_for('page_not_found', current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route("/login", methods=['GET', 'POST'])
def login():
    current_year = datetime.now().year
    try:
        if request.method == 'POST':
            email = request.form['email']
            salt = 'wqPDlMOPw5PChcOkwoHDn8OZw6I='
            passwo = hash2(hash1(hash0(encrypt(key="Key", clear=encrypt_password(request.form['psw'] + salt)))))
            user = Users.query.filter_by(email=encrypt(email)).first()
            if user:
                psw = Users.query.filter_by(psw=encrypt(passwo)).first()
                if psw:
                    msg = "You had logged in our sites."
                    sub = "Login Detected!!"
                    mail(request.form['email'], msg, sub)
                    login_user(user)
                    flash('Logged in successfully.')
                    return redirect(url_for('home', current_year=current_year))
                else:
                    msg = "Someone is trying to login in our site using your credentials."
                    sub = "Someone is trying to login."
                    mail(request.form['email'], msg, sub)
                    flash("You had entered wrong Password!")
                    return render_template("login.html", current_year=current_year)
            else:
                flash("Their is no account found on the given email!")
                return render_template("login.html", current_year=current_year)
        return render_template('login.html', current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    current_year = datetime.now().year
    try:
        if request.method == 'POST':
            email = request.form['email']
            blocked = Blocked.query.filter_by(email=encrypt(email)).first()
            if 'name' in request.form and 'Dob' in request.form and 'Gender' in request.form and \
                    'email' in request.form and 'phone' in request.form:
                if blocked:
                    flash("Given email is blocked for certain reason!Use another email!")
                    return redirect(url_for("signup", current_year=current_year))
                else:
                    email = request.form['email']
                    user = Users.query.filter_by(email=email).first()
                    salt = 'wqPDlMOPw5PChcOkwoHDn8OZw6I='
                    Password = \
                        hash2(hash1(hash0(encrypt(key="Key", clear=encrypt_password(request.form['psw'] + salt)))))
                    if user:
                        flash("You already having the account on this email!")
                        return render_template("login.html", current_year=current_year)
                    else:
                        if request.form['retype'] == request.form['psw']:
                            msg = "Congratulation, Your account has Created Successfully"
                            subject = "Your account has created successfully!"
                            if current_user.is_authenticated:
                                if current_user.account_type == "Owner":
                                    User = Users(name=encrypt(request.form['name']), dob=encrypt(request.form['Dob']),
                                                 gender=encrypt(request.form.get('Gender')),
                                                 psw=encrypt(Password), email=encrypt(request.form['email']),
                                                 phone=encrypt(request.form['phone']),
                                                 account_type=request.form.get('type'))
                            else:
                                User = Users(name=encrypt(request.form['name']), dob=encrypt(request.form['Dob']),
                                             gender=encrypt(request.form.get('Gender')),
                                             psw=encrypt(Password), email=encrypt(request.form['email']),
                                             phone=encrypt(request.form['phone']), account_type="User")
                            db.session.add(User)
                            db.session.commit()
                            mail(request.form['email'], msg, subject)
                            flash("Your account has been created!")
                            if current_user.is_authenticated:
                                if current_user.account_type == "Owner":
                                    return redirect(url_for("home", current_year=current_year))
                            else:
                                return redirect(url_for("login", current_year=current_year))
                        else:
                            flash("Both password doesn't matches!")
                            return render_template("signup.html", current_year=current_year)
            else:
                flash("Fill all the field!")
                return render_template("signup.html", current_year=current_year)
        return render_template('signup.html', current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    current_year = datetime.now().year
    try:
        user = Users.query.filter_by(id=current_user.id).first()
        if user:
            apply = applied.query.filter_by(email=user.email).first()
            accept = accepted.query.filter_by(email=user.email).first()
            select = selected.query.filter_by(email=user.email).first()
            msg = f"Your account containing {decrypt(user.email)} was deleted successfully."
            sub = "Acknowledgement for the deletion of your account!!"
            mail(decrypt(user.email), msg, sub)
            if apply:
                delete_pdf(apply.pdf_name)
                db.session.delete(apply)
            elif accept:
                delete_pdf(accept.pdf_name)
                db.session.delete(accept)
            elif select:
                delete_pdf(select.pdf_name)
                db.session.delete(select)
            db.session.delete(user)
            db.session.commit()
            flash("Your account was deleted successfully!")
            return redirect(url_for('login', current_year=current_year))
        else:
            flash("User not found!")
            return render_template("wrong.html", current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("block_user")}/<int:use>', methods=['GET', 'POST'])
@login_required
def block_user(use):
    current_year = datetime.now().year
    try:
        user = Users.query.filter_by(id=use).first()
        if user:
            block = Blocked(email=user.email)
            msg = f"Your account containing {decrypt(user.email)} was blocked temporarily.If you have any queries " \
                  f"regarding this please visit us."
            sub = "Acknowledgement for the Blocking of your account!!"
            mail(decrypt(user.email), msg, sub)
            db.session.add(block)
            db.session.delete(user)
            db.session.commit()
            flash("The account was blocked!")
            return redirect(url_for("user_list", current_year=current_year))
        else:
            flash("User not found!")
            return render_template("wrong.html", current_year=current_year)

    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("block_list")}', methods=['GET', 'POST'])
def block_list():
    current_year = datetime.now().year
    try:
        bans = db.session.query(Blocked).all()
        row = []
        for ban in bans:
            email = decrypt(ban.email)
            row.append((ban.id, email))
        return render_template('block_list.html', data=row, current_year=current_year)
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


@app.route(f'/{encrypt("unblock_user")}/<int:use>', methods=['GET', 'POST'])
def unblock_user(use):
    current_year = datetime.now().year
    try:
        user = Blocked.query.filter_by(id=use).first()
        db.session.delete(user)
        db.session.commit()
        flash("Account Unblocked!")
        return redirect(url_for("block_list", current_year=current_year))
    except Exception as e:
        flash(str(e))
        return render_template("wrong.html", current_year=current_year)


def save_pdf(file, name):
    path = os.path.join(app.config['UPLOAD_FOLDER'], name)
    with open(path, 'wb') as f:
        f.write(file)


def delete_pdf(name):
    directory = app.config['UPLOAD_FOLDER']
    os.remove(os.path.join(directory, name))


@app.errorhandler(404)
def page_not_found(e):
    current_year = datetime.now().year
    return render_template("404.html", current_year=current_year), 404


@app.errorhandler(500)
def page_not_found(e):
    current_year = datetime.now().year
    return render_template("500.html", current_year=current_year), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
