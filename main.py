from flask import Flask, render_template, request, redirect, flash, url_for, make_response, get_flashed_messages
import smtplib
from Dec import decrypt
from flask_sqlalchemy import SQLAlchemy
from pytz import timezone
import pymysql
import io
from datetime import datetime
from encrpyt import encrypt, encrypt_password, hash0, hash1, hash2
from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my-secret-key'
app.config[
    'SQLALCHEMY_DATABASE_URI'] = f'{decrypt("w4DDnsOWw6PDkcKfwpDDpMOSw7LDhsOWw4_CrMKUwqPCksOaw5TDrcKNwrXDhMOlw5jDq1DDncOJwqrChcKYwqPDnsOUw5fCgcOXw43DqMOGw5nCksOVw5TDoMKMw5DDjMOe")}'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You Have Been Logged Out!")
    return redirect('/login')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', data=current_user)


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
    phone = db.Column(db.BigInteger, nullable=False)
    psw = db.Column(db.String(255), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))
    account_type = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'


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
    pincode = db.Column(db.BigInteger, nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.BigInteger, nullable=False)
    pdf_name = db.Column(db.String(255))
    pdf_data = db.Column(db.LargeBinary(length=5 * 1024 * 1024))
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
    pincode = db.Column(db.BigInteger, nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.BigInteger, nullable=False)
    pdf_name = db.Column(db.String(255))
    pdf_data = db.Column(db.LargeBinary(length=5 * 1024 * 1024))
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
    pincode = db.Column(db.BigInteger, nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.BigInteger, nullable=False)
    pdf_name = db.Column(db.String(255))
    pdf_data = db.Column(db.LargeBinary(length=5 * 1024 * 1024))
    date_applied = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))


@app.route("/")
def home():
    return render_template('index.html')


@app.route("/user", methods=['GET', 'POST'])
@login_required
def user_list():
    if current_user.account_type == "Owner":
        data = db.session.query(Users).all()
        return render_template('user.html', data=data)
    else:
        return render_template("sorry.html")


@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    user = Users.query.get(user_id)
    if request.method == 'POST':
        user.name = request.form['name']
        user.dob = request.form['Dob']
        user.phone = request.form['phone']
        db.session.commit()
        flash('User information updated successfully')
        return redirect(url_for('dashboard', user_id=user.id))
    return render_template('update.html', user=user)


@app.route("/applied", methods=['GET', 'POST'])
@login_required
def applied_form_submission():
    file = request.files['pdf']
    name = file.filename
    data = file.read()
    if 'name' in request.form and 'jobpost' in request.form and 'Department' in request.form and 'Qualification' in request.form and 'Experience' in request.form and 'address' in request.form and 'Gender' in request.form and 'state' in request.form and 'Dob' in request.form and 'pincode' in request.form and 'email' in request.form and 'phone' in request.form:
        application = applied(user_id=current_user.id, name=request.form['name'],
                              post=request.form['jobpost'], department=request.form['Department'],
                              qualification=request.form['Qualification'], experience=request.form['Experience'],
                              address=request.form['address'], gender=request.form.get('Gender'),
                              state=request.form['state'], dob=request.form['Dob'], pincode=request.form['pincode'],
                              email=request.form['email'], phone=request.form['phone'], pdf_name=name, pdf_data=data)
        db.session.add(application)
        db.session.commit()
        return render_template("jobsuccess.html")
    else:
        return render_template("wrong.html")


@app.route('/csejobs', methods=['GET', 'POST'])
@login_required
def cse_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'CSE').all()
    return render_template('applyjobs.html', data=data)


@app.route('/itjobs', methods=['GET', 'POST'])
@login_required
def it_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'IT').all()
    return render_template('applyjobs.html', data=data)


@app.route('/ecejobs', methods=['GET', 'POST'])
@login_required
def ece_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'ECE').all()
    return render_template('applyjobs.html', data=data)


@app.route('/aidsjobs', methods=['GET', 'POST'])
@login_required
def aids_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'AIDS').all()
    return render_template('applyjobs.html', data=data)


@app.route('/mechjobs', methods=['GET', 'POST'])
@login_required
def mech_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'MECH').all()
    return render_template('applyjobs.html', data=data)


@app.route('/mbajobs', methods=['GET', 'POST'])
@login_required
def mba_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'MBA').all()
    return render_template('applyjobs.html', data=data)


@app.route('/eeejobs', methods=['GET', 'POST'])
@login_required
def eee_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'EEE').all()
    return render_template('applyjobs.html', data=data)


@app.route('/otherjobs', methods=['GET', 'POST'])
@login_required
def other_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'OTHERS').all()
    return render_template('applyjobs.html', data=data)


@app.route('/otherjobs', methods=['GET', 'POST'])
@login_required
def civil_jobs():
    data = db.session.query(Jobs).filter(Jobs.department == 'CIVIL').all()
    return render_template('applyjobs.html', data=data)


@app.route('/apply_job', methods=['GET', 'POST'])
@login_required
def apply_job():
    return render_template("application.html")


@app.route('/view_pdf/<int:id>')
def view_pdf(id):
    apply = db.session.query(applied).filter_by(id=id).first()
    pdf_data = apply.pdf_data
    response = make_response(pdf_data)
    response.headers.set('Content-Disposition', 'attachment', filename='file.pdf')
    response.headers.set('Content-Type', 'application/pdf')
    return response


@app.route('/applicaton_display')
@login_required
def applications_display():
    if current_user.account_type == "Owner" or current_user.account_type == "Admin":
        data = db.session.query(applied).all()
        return render_template('application_list.html', data=data)
    else:
        return redirect(url_for('page_not_found'))


@app.route('/move_to_accepted/<int:id>', methods=['POST'])
@login_required
def move_to_accepted(id):
    applied_data = db.session.query(applied).filter_by(id=id).first()
    Email = applied_data.email
    if applied_data:
        MY_EMAIL = "test5test005@gmail.com"
        MY_PASSWORD = decrypt("wr3DmMOcw57DnMOewpLDjMOaw57DgMOOw5nDoMOaw64=")

        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(MY_EMAIL, MY_PASSWORD)
            connection.sendmail(
                from_addr=MY_EMAIL,
                to_addrs=Email,
                msg=f"Subject: Your application has been approved!\n\nCongratulation, Your application was approved for"
                    f" the position of {applied_data.post}."
                    f"Within three working days, you must attend the college for an interview (time: 10AM–11AM)."
                    f"Your user id is {applied_data.user_id}."
            )

        accepted_data = accepted(accepted_user_id=current_user.id, user_id=applied_data.user_id, name=applied_data.name,
                                 post=applied_data.post, address=applied_data.address,
                                 department=applied_data.department, experience=applied_data.experience,
                                 qualification=applied_data.qualification, gender=applied_data.gender,
                                 dob=applied_data.dob, pincode=applied_data.pincode, state=applied_data.state,
                                 email=applied_data.email, phone=applied_data.phone, pdf_data=applied_data.pdf_data)
        db.session.add(accepted_data)
        db.session.delete(applied_data)
        db.session.commit()
        flash("Application has been Accepted!")
    else:
        flash("Application not found or has already been accepted.")

    return redirect(url_for('applications_display'))


@app.route('/accepted_list', methods=['GET', 'POST'])
@login_required
def accepted_list():
    if current_user.account_type == "Owner" or current_user.account_type == "Admin":
        data = db.session.query(accepted).all()
        return render_template('Accepted_list.html', data=data)
    else:
        return redirect(url_for('page_not_found'))


@app.route('/accepted_view_pdf/<int:id>')
def accepted_view_pdf(id):
    apply = db.session.query(accepted).filter_by(id=id).first()
    pdf_data = apply.pdf_data
    response = make_response(pdf_data)
    response.headers.set('Content-Disposition', 'attachment', filename='file.pdf')
    response.headers.set('Content-Type', 'application/pdf')
    return response


@app.route('/data/remove/<int:id>', methods=['POST'])
@login_required
def remove_user(id):
    data = db.session.query(accepted).filter_by(id=id).first()
    db.session.delete(data)
    db.session.commit()
    return redirect(url_for("accepted_list"))


@app.route('/move_to_selected/<int:id>', methods=['POST'])
@login_required
def move_to_selected(id):
    applied_data = db.session.query(accepted).filter_by(id=id).first()
    Email = applied_data.email
    if applied_data:
        MY_EMAIL = "test5test005@gmail.com"
        MY_PASSWORD = decrypt("wr3DmMOcw57DnMOewpLDjMOaw57DgMOOw5nDoMOaw64=")

        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(MY_EMAIL, MY_PASSWORD)
            connection.sendmail(
                from_addr=MY_EMAIL,
                to_addrs=Email,
                msg=f"Subject: Your application has been approved!\n\nCongratulation, Your are selected as the"
                    f" {applied_data.post}.Your User id is {applied_data.user_id}"
            )
        selected_data = selected(accepted_user_id=applied_data.accepted_user_id, selected_user_id=current_user.id,
                                 user_id=applied_data.user_id, name=applied_data.name,
                                 post=applied_data.post, address=applied_data.address,
                                 department=applied_data.department, experience=applied_data.experience,
                                 qualification=applied_data.qualification, gender=applied_data.gender,
                                 dob=applied_data.dob, pincode=applied_data.pincode, state=applied_data.state,
                                 email=applied_data.email, phone=applied_data.phone, pdf_data=applied_data.pdf_data)
        db.session.add(selected_data)
        db.session.delete(applied_data)
        db.session.commit()

        flash("Application has been Selected!")
    else:
        flash("Application not found or has already been Selected.")

    return redirect(url_for('accepted_list'))


@app.route('/data/reject/<int:id>', methods=['POST'])
@login_required
def reject(id):
    data = db.session.query(applied).filter_by(id=id).first()
    MY_EMAIL = "test5test005@gmail.com"
    MY_PASSWORD = decrypt("wr3DmMOcw57DnMOewpLDjMOaw57DgMOOw5nDoMOaw64=")
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(MY_EMAIL, MY_PASSWORD)
        connection.sendmail(
            from_addr=MY_EMAIL,
            to_addrs=data.email,
            msg=f"Subject: Your Application has been Rejected!!\n\nWe regret to inform you that we have rejected your "
                f"application for the position of {data.post}."
        )
    db.session.delete(data)
    db.session.commit()
    return redirect(url_for('applications_display'))


@app.route('/selected_list', methods=['GET', 'POST'])
@login_required
def selected_list():
    if current_user.account_type == "Owner" or current_user.account_type == "Admin":
        data = db.session.query(selected).all()
        return render_template('selected_list.html', data=data)
    else:
        return redirect(url_for('page_not_found'))


@app.route('/selected_view_pdf/<int:id>')
def selected_view_pdf(id):
    apply = db.session.query(selected).filter_by(id=id).first()
    pdf_data = apply.pdf_data
    response = make_response(pdf_data)
    response.headers.set('Content-Disposition', 'attachment', filename='file.pdf')
    response.headers.set('Content-Type', 'application/pdf')
    return response


@app.route('/data/reject_user/<int:id>', methods=['POST'])
@login_required
def reject_user(id):
    data = db.session.query(selected).filter_by(id=id).first()
    db.session.delete(data)
    db.session.commit()
    return redirect(url_for("selected_list"))


@app.route('/Jobs')
@login_required
def display_jobs():
    if current_user.account_type == "Owner" or current_user.account_type == "Admin":
        data = db.session.query(Jobs).all()
        return render_template('Jobs.html', data=data)
    else:
        return redirect(url_for('page_not_found'))


@app.route('/data/delete/<int:id>', methods=['POST'])
@login_required
def delete_data(id):
    data = db.session.query(Jobs).filter_by(id=id).first()
    if current_user.account_type == "Owner" or current_user.id == data.post_job_id:
        db.session.delete(data)
        db.session.commit()
        return redirect(url_for('display_jobs'))
    else:
        return render_template("sorry.html")


@app.route('/post_job', methods=['GET', 'POST'])
@login_required
def post_job():
    if request.method == 'POST':
        Job = Jobs(title=request.form['job-title'], post_job_id=current_user.id,
                   department=request.form.get('Department'),
                   description=request.form['job-description'],
                   requirement=request.form['job-requirements'], job_type=request.form.get('job-type'),
                   category=request.form.get('job-category'))
        db.session.add(Job)
        db.session.commit()
        return "Job posted successfully!!"
    else:
        if current_user.account_type == "Owner" or current_user.account_type == "Admin":
            return render_template('jobpost.html')
        else:
            return redirect(url_for('page_not_found'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        salt = 'wqPDlMOPw5PChcOkwoHDn8OZw6I='
        passwo = hash2(hash1(hash0(encrypt(key="ponjesly", clear=encrypt_password(request.form['psw'] + salt)))))
        user = Users.query.filter_by(email=email).first()
        MY_EMAIL = "test5test005@gmail.com"
        MY_PASSWORD = decrypt("wr3DmMOcw57DnMOewpLDjMOaw57DgMOOw5nDoMOaw64=")
        if user:
            psw = Users.query.filter_by(psw=passwo).first()
            if psw:
                with smtplib.SMTP("smtp.gmail.com") as connection:
                    connection.starttls()
                    connection.login(MY_EMAIL, MY_PASSWORD)
                    connection.sendmail(
                        from_addr=MY_EMAIL,
                        to_addrs=request.form['email'],
                        msg="Subject: Login Detected!!\n\nYou had logged in our sites."
                    )
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('home'))
            else:
                with smtplib.SMTP("smtp.gmail.com") as connection:
                    connection.starttls()
                    connection.login(MY_EMAIL, MY_PASSWORD)
                    connection.sendmail(
                        from_addr=MY_EMAIL,
                        to_addrs=request.form['email'],
                        msg=f"Subject: Someone is trying to login.\n\nSomeone is trying to login in our site using "
                            f"your credentials,"
                    )
                flash('Invalid email or password')
                return redirect('/login')
        else:
            return "Email doesn't exists!"
    return render_template('login.html')


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        user = Users.query.filter_by(email=email).first()
        salt = 'wqPDlMOPw5PChcOkwoHDn8OZw6I='
        Password = hash2(hash1(hash0(encrypt(key="ponjesly", clear=encrypt_password(request.form['psw'] + salt)))))
        if user:
            return "Email already exists!"
        else:
            if request.form['psw'] == request.form['retype']:
                MY_EMAIL = "test5test005@gmail.com"
                MY_PASSWORD = decrypt("wr3DmMOcw57DnMOewpLDjMOaw57DgMOOw5nDoMOaw64=")

                with smtplib.SMTP("smtp.gmail.com") as connection:
                    connection.starttls()
                    connection.login(MY_EMAIL, MY_PASSWORD)
                    connection.sendmail(
                        from_addr=MY_EMAIL,
                        to_addrs=request.form['email'],
                        msg=f"Subject: Your account has created successfully!\n\nCongratulation, Your account has "
                            f"Created Successfully"
                    )
                User = Users(name=request.form['name'], dob=request.form['Dob'], gender=request.form.get('Gender'),
                             psw=Password,
                             email=request.form['email'], phone=request.form['phone'],
                             account_type=request.form.get('type'))
                db.session.add(User)
                db.session.commit()
                return redirect(url_for('login'))
            else:
                return redirect(url_for('signup'))
    return render_template('signup.html')


@app.route('/delete_user', methods=['POST'])
def delete_user():
    user = Users.query.filter_by(id=current_user.id).first()

    if user:
        MY_EMAIL = "test5test005@gmail.com"
        MY_PASSWORD = decrypt("wr3DmMOcw57DnMOewpLDjMOaw57DgMOOw5nDoMOaw64=")
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(MY_EMAIL, MY_PASSWORD)
            connection.sendmail(
                from_addr=MY_EMAIL,
                to_addrs=user.email,
                msg=f"Subject:Acknowledgement for the deletion of your account!!\n\nYour account containing "
                    f"{user.email} was deleted successfully."
            )
        db.session.delete(user)
        db.session.commit()
        return redirect('/login')
    else:
        return "No user found."


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
