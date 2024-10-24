from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import bcrypt
from flask_mail import Mail, Message
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/limo'

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dukelimo2001@gmail.com'
app.config['MAIL_PASSWORD'] = 'zgbj spiq xcer myfg'  # Use environment variables for security
app.config['MAIL_DEFAULT_SENDER'] = 'dukelimo2001@gmail.com'

mail = Mail(app)
mongo = PyMongo(app)

# User Registration Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store the user in MongoDB
        mongo.db.users.insert_one({
            'username': username,
            'password': hashed_password,
            'email': email
        })
        
        flash('Sign up successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# User Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = mongo.db.users.find_one({'username': username})
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            flash('Login successful!', 'success')
            return redirect(url_for('index'))  # Redirect to your main page after login
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Main Index Route
@app.route('/')
def index():
    return render_template('index.html')

# Route to Request Password Reset
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = mongo.db.users.find_one({'email': email})

        if user:
            # Create a password reset token
            token = jwt.encode({'username': user['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
            reset_link = url_for('reset_password', token=token, _external=True)

            # Send the password reset email
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_link}'
            mail.send(msg)

            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('No account found with that email address.', 'danger')

    return render_template('reset_request.html')

# Password Reset Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode the token to get the username
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = data['username']
    except jwt.ExpiredSignatureError:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('reset_request'))
    except jwt.InvalidTokenError:
        flash('Invalid token. Please request a new password reset.', 'danger')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update the user's password in MongoDB
        mongo.db.users.update_one({'username': username}, {'$set': {'password': hashed_password}})
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Route to Add Contact Details
@app.route('/add_contact', methods=['GET', 'POST'])
def add_contact():
    if request.method == 'POST':
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        address = request.form.get('address')
        registration_number = request.form.get('registration_number')

        if not all([name, mobile, email, address, registration_number]):
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('add_contact'))

        try:
            mongo.db.contacts.insert_one({
                'name': name,
                'mobile': mobile,
                'email': email,
                'address': address,
                'registration_number': registration_number
            })
            flash('Contact added successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')

        return redirect(url_for('index'))

    return render_template('add_contact.html')

# Route to Search for Contacts
@app.route('/search_contact', methods=['GET', 'POST'])
def search_contact():
    contact = None
    if request.method == 'POST':
        registration_number = request.form.get('registration_number')

        # Debugging statement
        print(f"Searching for registration number: {registration_number}")

        # Query the database
        contact = mongo.db.contacts.find_one({'registration_number': registration_number})

       
        if contact:
            print(f"Found contact: {contact}")
            return render_template('search_results.html', contact=contact)
        else:
            print("No contact found.")
            flash('No contact found with that registration number.', 'danger')

    return render_template('search_contact.html')

if __name__ == '__main__':
    app.run(debug=True)
