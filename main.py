from flask import render_template, Flask, request
import smtplib
from random import randint
from Dec import decrypt
import mysql.connector

app = Flask(__name__)

otp = []


@app.route("/")
def home():
    return render_template('index.html')


@app.route("/login")
def login():
    return render_template('login.html')


@app.route("/signup")
def signup():
    return render_template('signup.html')


@app.route('/submit', methods=['POST'])
def send_otp():
    email = request.form['email']
    generated_otp = generate_otp()

    send_otp_to_email(email, generated_otp)

    # Store the email and OTP in the global list
    otp.append({'email': email, 'otp': generated_otp})

    return render_template('verifyotp.html', email=email)


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


if __name__ == "__main__":
    app.run(debug=True)
