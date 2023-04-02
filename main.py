from flask import Flask, render_template, request
import smtplib
from random import randint

from sqlalchemy.sql.functions import user

from Dec import decrypt
from flask_sqlalchemy import SQLAlchemy
import pymysql
from datetime import datetime
from encrpyt import encrypt, encrypt_password, hash

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Passw0rd123@localhost/college'
db = SQLAlchemy(app)
otp = []


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(200), nullable=False)
    lname = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    psw = db.Column(db.String(500), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    account_type = db.Column(db.String(50), nullable=False)


@app.route("/")
def home():
    return render_template('index.html')


@app.route("/login")
def login():
    return render_template('login.html')


@app.route("/signup")
def signup():
    return render_template('signup.html')


@app.route("/sendsignup_otp", methods=["POST"])
def sendsignup_otp():
    email = request.form['email']

    # Check if the email already exists in the database
    user = Users.query.filter_by(email=email).first()
    if user:
        return "Email already exists!"
    else:
        generated_otp = generate_otp()

        send_otp_to_email(email, generated_otp)
        User = Users(fname=request.form['fname'], lname=request.form['lname'],
                     psw=hash(encrypt(key="ponjesly", clear=encrypt_password(request.form['psw']))),
                     email=request.form['email'], account_type=request.form.get('type'))
        db.session.add(User)
        db.session.commit()

        # Store the email and OTP in the global list
        otp.append({'email': email, 'otp': generated_otp})
        return render_template("verifyotp2.html")


@app.route('/submitlog', methods=['POST'])
def sendlogin_otp():
    email = request.form['email']
    passwo = hash(encrypt(key="ponjesly", clear=encrypt_password(request.form['psw'])))
    # Check if the email already exists in the database
    user = Users.query.filter_by(email=email).first()
    if user:
        psw = Users.query.filter_by(psw=passwo).first()
        if psw:
            generated_otp = generate_otp()
            send_otp_to_email(email, generated_otp)

            # Store the email and OTP in the global list
            otp.append({'email': email, 'otp': generated_otp})

            return render_template('verifyotp.html', email=email)
        else:
            return "Your email or password wrong"

    else:
        return "Email doesn't exists!"


@app.route('/verify', methods=['POST'])
def verify_otp():
    entered_otp = request.form['otp']

    for i in range(len(otp)):
        if otp[i]['otp'] == entered_otp:
            # Remove the verified OTP from the global list
            del otp[i]
            return "OTP verified successfully!"
        else:
            return "Invalid OTP"
    # If the email is not found in the global list, return an error message
    return "Email not found"


def generate_otp():
    Otp = ''
    for i in range(4):
        Otp += str(randint(0, 9))

    return Otp


def send_otp_to_email(email, Otp):
    MY_EMAIL = "test5test005@gmail.com"
    MY_PASSWORD = decrypt("wr3DmMOcw57DnMOewpLDjMOaw57DgMOOw5nDoMOaw64=")

    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(MY_EMAIL, MY_PASSWORD)
        connection.sendmail(
            from_addr=MY_EMAIL,
            to_addrs=email,
            msg=f"Subject: OTP\n\nYour OTP is {Otp}"
        )


def delete_user():
    email = request.form['email']

    user = Users.query.filter_by(email=email).first()

    if user:
        db.session.delete(user)
        db.session.commit()
        return f"User with email {email} deleted successfully."
    else:
        return f"No user found with email {email}."


if __name__ == "__main__":
    with app.app_context():  # create the application context
        db.create_all()  # create the database tables
    app.run(debug=True)
