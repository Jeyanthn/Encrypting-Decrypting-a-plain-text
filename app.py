import os
from flask import Flask, request, render_template, flash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

# Initialize Flask app and CSRF protection
app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')

# Form classes for handling input
class EncryptForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    data_to_encrypt = StringField('Data to Encrypt', validators=[DataRequired()])
    submit = SubmitField('Encrypt')

class DecryptForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    data_to_decrypt = StringField('Data to Decrypt (Hex)', validators=[DataRequired()])
    salt = StringField('Salt (Hex)', validators=[DataRequired()])
    submit = SubmitField('Decrypt')

# Function to generate a key using PBKDF2
def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

# Function to encrypt data
def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    try:
        iv = bytes.fromhex(encrypted_data[:32])
        data = bytes.fromhex(encrypted_data[32:])
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    form = EncryptForm()
    if form.validate_on_submit():
        password = form.password.data
        data_to_encrypt = form.data_to_encrypt.data

        try:
            # Generate key and salt
            key, salt = generate_key(password)

            # Encrypt data
            encrypted_data = encrypt_data(data_to_encrypt, key)

            return render_template('encrypt.html', form=form, encrypted_data=encrypted_data.hex(), salt=salt.hex())
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('encrypt.html', form=form)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    form = DecryptForm()
    if form.validate_on_submit():
        password = form.password.data
        encrypted_data = form.data_to_decrypt.data
        salt = form.salt.data

        try:
            # Generate key using the provided salt
            key, _ = generate_key(password, bytes.fromhex(salt))

            # Decrypt data
            decrypted_data = decrypt_data(encrypted_data, key)

            return render_template('decrypt.html', form=form, decrypted_data=decrypted_data)
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('decrypt.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
