from flask import Flask, jsonify, render_template, redirect, request, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.file import FileAllowed, FileField
from wtforms import StringField, TextAreaField, DateField, SelectField, PasswordField, SubmitField
from wtforms.validators import Optional, DataRequired, Email, InputRequired, Length, EqualTo
from werkzeug.utils import secure_filename

import os
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from datetime import datetime
from forms import ClientReviewForm, ContactForm, ReviewForm

# Setup
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, static_folder='static')
CORS(app)
csrf = CSRFProtect(app)

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = 'django-insecure-$(u3n^8fv1nt4%1t@+@--gp(ap2k0b^ti$qta8_78hv_7017bq'  # Or load from .env securely
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'profile_pics')

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



SECRET_KEY = 'django-insecure-$(u3n^8fv1nt4%1t@+@--gp(ap2k0b^ti$qta8_78hv_7017bq'
ALGORITHM = 'HS256'



# Database Models
class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=True)  
    gender = db.Column(db.String(10), nullable=True)
    role = db.Column(db.String(50), nullable=False, default="user")
    is_admin = db.Column(db.Boolean, default=False)
    
    # User model
    profile = db.relationship('UserProfile', backref='user', cascade="all, delete", passive_deletes=True, uselist=False)
    
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    profile_picture = db.Column(db.String(200), default='profile_pics/default_profile.png')
    bio = db.Column(db.Text, nullable=True)
    birth_date = db.Column(db.Date, nullable=True)

    def __repr__(self):
        return f"{self.user.name}'s Profile"
    

class EditUserForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])


class UserProfileForm(FlaskForm):
    profile_picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    bio = TextAreaField('Bio')
    birth_date = DateField('Birth Date')



class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[InputRequired(), Length(min=3, max=50)])
    email = StringField('Email Address', validators=[InputRequired(), Email()])
    mobile = StringField('Phone Number', validators=[InputRequired(), Length(min=10, max=15)])
    address = TextAreaField('Address', validators=[InputRequired(), Length(min=10, max=255)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message="Passwords must match")])




class Section(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    banner = db.Column(db.String(255))  # or appropriate type

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "banner": url_for('static', filename=self.banner, _external=True) if self.banner else None
        }
    


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2))
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'))
    cover_image = db.Column(db.String(255))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author,
            'description': self.description,
            'price': str(self.price),
            'cover_image': (
                url_for('static', filename=self.cover_image.lstrip('/'), _external=True)
                if self.cover_image else None
            )
        }


class Review(db.Model):
    __tablename__ = 'reviews'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    book = db.relationship('Book', backref=db.backref('reviews', lazy=True))
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))

    __table_args__ = (
        db.UniqueConstraint('book_id', 'user_id', name='unique_review_per_user_per_book'),
    )

    def __repr__(self):
        return f"{self.user.name} - {self.book.title} ({self.rating}⭐)"  # Fixed: username -> name


class CartItem(db.Model):
    __tablename__ = 'cart_items'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    book = db.relationship('Book', backref=db.backref('cart_items', lazy=True))

    @property
    def subtotal(self):
        return self.book.price * self.quantity

    def __repr__(self):
        return f'{self.book.title} x {self.quantity}'
    

class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    total_price = db.Column(db.Numeric(10, 2), default=0.0)
    payment_status = db.Column(db.String(20), default='pending')
    order_status = db.Column(db.String(20), default='processing')

    # Shipping details
    name = db.Column(db.String(100), default='Customer')
    phone = db.Column(db.String(15), default='0000000000')
    email = db.Column(db.String(120), default='noemail@example.com')
    address = db.Column(db.Text, default='No address provided')
    locality = db.Column(db.String(100), default='Unknown')
    city = db.Column(db.String(100), default='Unknown City')
    state = db.Column(db.String(100), default='Unknown State')
    pincode = db.Column(db.String(10), default='000000')
    payment_method = db.Column(db.String(20), default='Unknown')
    ordered_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    items = db.relationship('OrderItem', backref='order', lazy=True)

    def __repr__(self):
        return f'<Order #{self.id} by {self.user.name if self.user else "Guest"}>'  # Fixed: username -> name

    def calculate_total(self):
        self.total_price = sum(item.subtotal() for item in self.items)
        db.session.commit()


class OrderItem(db.Model):
    __tablename__ = 'order_items'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(8, 2), nullable=False)

    book = db.relationship('Book', backref=db.backref('order_items', lazy=True))

    def __repr__(self):
        return f'{self.book.title} x {self.quantity} (Order #{self.order.id})'

    def subtotal(self):
        return self.price * self.quantity


class ClientReview(db.Model):
    __tablename__ = 'client_reviews'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), default="")
    image = db.Column(db.String(255), nullable=True)  # Storing image path as a string
    review = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, default=5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'{self.name} - {self.rating}⭐'


class Wishlist(db.Model):
    __tablename__ = 'wishlists'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    added_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('wishlist_items', lazy=True))
    book = db.relationship('Book', backref=db.backref('wishlist_items', lazy=True))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'book_id', name='unique_wishlist_item'),
    )

    def __repr__(self):
        return f'{self.user.name} - {self.book.title}'  # Fixed: username -> name



class ShippingForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=10, max=10)])
    email = StringField('Email', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    pincode = StringField('Pincode', validators=[DataRequired(), Length(min=6, max=6)])
    locality = StringField('Locality', validators=[DataRequired()])
    submit = SubmitField('Proceed to Payment')


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    address = db.Column(db.String(200))
    city = db.Column(db.String(100))

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    message = db.Column(db.Text)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




@app.context_processor
def inject_sections():
    sections = Section.query.order_by(Section.name).all()
    return dict(sections=sections)





# Initialize database and create admin user
with app.app_context():
    db.create_all()
    # Check if an admin user already exists
    if not User.query.filter_by(role="admin").first():
        admin_user = User(
            name="Admin", 
            email="admin@gmail.com", 
            mobile="1234567890", 
            role="admin", 
            is_admin=True  
        )
        admin_user.set_password("admin123")  # Set a default password
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created with email: admin@gmail.com and password: admin123")




@app.route('/api/data', methods=['GET'])
def secure_data():
    payload, error_response, status_code = verify_jwt_token()
    if error_response:
        return jsonify(error_response), status_code

    return jsonify({
        'message': 'Hello from Flask!',
        'user_id': payload.get('user_id'),
        'books': ['Flask Book 1', 'Flask Book 2']
    })




def verify_jwt_token():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, {'error': 'Missing or malformed token'}, 401

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload, None, None
    except ExpiredSignatureError:
        return None, {'error': 'Token has expired'}, 401
    except InvalidTokenError:
        return None, {'error': 'Invalid token'}, 401



@app.route('/api/sections', methods=['GET'])
def get_sections():
    sections = Section.query.all()
    return jsonify([s.to_dict() for s in sections]), 200

@app.route('/api/sections/<int:id>', methods=['GET'])
def get_section(id):
    section = Section.query.get_or_404(id)
    return jsonify(section.to_dict()), 200

@app.route('/api/sections', methods=['POST'])
def create_section():
    payload, error_response, status_code = verify_jwt_token()
    if error_response:
        return jsonify(error_response), status_code

    data = request.get_json()
    section = Section(
        name=data['name'],
        description=data.get('description', ''),
        banner=data.get('banner')
    )
    db.session.add(section)
    db.session.commit()
    return jsonify(section.to_dict()), 201



@app.route('/api/sections/<int:id>', methods=['PUT'])
def update_section(id):
    payload, error_response, status_code = verify_jwt_token()
    if error_response:
        return jsonify(error_response), status_code

    section = Section.query.get_or_404(id)
    data = request.get_json()
    section.name = data.get('name', section.name)
    section.description = data.get('description', section.description)
    section.banner = data.get('banner', section.banner)
    db.session.commit()
    return jsonify(section.to_dict()), 200



@app.route('/api/sections/<int:id>', methods=['DELETE'])
def delete_section(id):
    payload, error_response, status_code = verify_jwt_token()
    if error_response:
        return jsonify(error_response), status_code

    section = Section.query.get_or_404(id)
    db.session.delete(section)
    db.session.commit()
    return jsonify({'message': 'Section deleted'}), 200



@app.route('/api/sections/<int:section_id>/books', methods=['GET'])
def get_books_by_section(section_id):
    books = Book.query.filter_by(section_id=section_id).all()

    return jsonify([
        {
            "id": book.id,
            "title": book.title,
            "author": book.author,
            "cover_image": url_for('static', filename=f'uploads/covers/{book.cover_image.split("/")[-1]}', _external=True)

        }
        for book in books
    ])


@app.route("/api/books", methods=["GET"])
def get_books():
    books = Book.query.all()
    base_url = request.host_url.rstrip('/')  # http://127.0.0.1:5000

    def serialize_book(book):
        
        cover_url = f"{base_url}/static/{book.cover_image.lstrip('/')}" if book.cover_image else None
        return {
            "id": book.id,
            "title": book.title,
            "author": book.author,
            "price": book.price,
            "description": book.description,
            "cover_image": cover_url
        }

    return jsonify([serialize_book(book) for book in books])
    
@app.route('/api/books/<int:book_id>')
def get_book(book_id):
    book = Book.query.get_or_404(book_id)
    return jsonify({
        'id': book.id,
        'title': book.title,
        'author': book.author,
        'description': book.description,
        'price': book.price,
        'cover_image': url_for('static', filename=book.cover_image.lstrip('/'), _external=True)

    })



@app.route('/api/books', methods=['POST'])
def create_book():
    payload, error_response, status_code = verify_jwt_token()
    if error_response:
        return jsonify(error_response), status_code

    data = request.get_json()
    book = Book(
        title=data['title'],
        author=data['author'],
        description=data.get('description', ''),
        price=data['price'],
        section_id=data.get('section_id'),
        cover_image=data.get('cover_image')
    )
    db.session.add(book)
    db.session.commit()
    return jsonify(book.to_dict()), 201



@app.route('/api/books/<int:id>', methods=['PUT'])
def update_book(id):
    payload, error_response, status_code = verify_jwt_token()
    if error_response:
        return jsonify(error_response), status_code

    book = Book.query.get_or_404(id)
    data = request.get_json()
    book.title = data.get('title', book.title)
    book.author = data.get('author', book.author)
    book.description = data.get('description', book.description)
    book.price = data.get('price', book.price)
    book.section_id = data.get('section_id', book.section_id)
    book.cover_image = data.get('cover_image', book.cover_image)

    db.session.commit()
    return jsonify(book.to_dict()), 200



@app.route('/api/books/<int:id>', methods=['DELETE'])
def delete_book(id):
    payload, error_response, status_code = verify_jwt_token()
    if error_response:
        return jsonify(error_response), status_code

    book = Book.query.get_or_404(id)
    db.session.delete(book)
    db.session.commit()
    return jsonify({'message': 'Book deleted'}), 200

@csrf.exempt
@app.route('/api/contact', methods=['POST'])
def api_contact():
    data = request.get_json()

    if not data or not all(k in data for k in ('name', 'email', 'message')):
        return jsonify({'error': 'Missing fields'}), 400

    new_contact = Contact(
        name=data['name'],
        email=data['email'],
        message=data['message']
    )
    db.session.add(new_contact)
    db.session.commit()

    return jsonify({'message': 'Contact message saved'}), 201



@app.route('/api/client_review', methods=['GET', 'POST'])
@csrf.exempt
def client_review_api():
    if request.method == 'GET':
        reviews = ClientReview.query.order_by(ClientReview.created_at.desc()).all()
        return jsonify([
            {
                'id': review.id,
                'name': review.name,
                'image': url_for('static', filename=review.image) if review.image else None,
                'review': review.review,
                'rating': review.rating,
                'created_at': review.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for review in reviews
        ])

    if request.method == 'POST':
        name = request.form.get('name')
        review_text = request.form.get('review')
        rating = request.form.get('rating')
        image = request.files.get('image')

        if not name or not review_text or not rating:
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            rating = int(rating)
        except ValueError:
            return jsonify({'error': 'Rating must be an integer'}), 400

        image_filename = None
        if image:
            upload_folder = os.path.join(app.root_path, 'static/uploads/reviews')
            os.makedirs(upload_folder, exist_ok=True)
            image_filename = secure_filename(image.filename)
            image_path = os.path.join(upload_folder, image_filename)
            image.save(image_path)

        new_review = ClientReview(
            name=name,
            review=review_text,
            rating=rating,
            image=f'uploads/reviews/{image_filename}' if image_filename else None
        )

        db.session.add(new_review)
        db.session.commit()

        return jsonify({'message': 'Review submitted successfully'}), 201
    


    

# -------------------- Home & Book Views --------------------

@app.route('/')
def index():
    return redirect(url_for('book_list'))


@app.route('/books', methods=['GET'])
def book_list():
    query = request.args.get('q', '')
    section_id = request.args.get('section')

    books = Book.query.all()
    if query:
        books = [book for book in books if query.lower() in book.title.lower()]
    if section_id:
        books = [book for book in books if book.section_id == int(section_id)]

    reviews = ClientReview.query.order_by(ClientReview.created_at.desc()).all()

    return render_template('bookstore/index.html', books=books, reviews=reviews, query=query, selected_section=section_id)


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return render_template('bookstore/dashboard.html')



@csrf.exempt
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        user = User.query.filter_by(email=email, role=role).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))  
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        mobile = form.mobile.data
        address = form.address.data
        gender = form.gender.data
        password = form.password.data

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        # Create the new user and hash the password
        new_user = User(name=name, email=email, mobile=mobile, address=address, gender=gender, role='user')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()  # Get the user ID without committing
        
        # Create a user profile
        profile = UserProfile(user_id=new_user.id)
        db.session.add(profile)
        
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    else:
        # Display form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "danger")

    return render_template("register.html", form=form)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))


@app.route('/profile')
@login_required
def view_profile():
    # Create profile if it doesn't exist
    if not current_user.profile:
        profile = UserProfile(user_id=current_user.id)
        db.session.add(profile)
        db.session.commit()
        db.session.refresh(current_user)  # Refresh the user object
    return render_template('profile.html', profile=current_user.profile)



@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user

    # Use `obj` only in GET to avoid pre-filling FileField with a string
    if request.method == 'GET':
        user_form = EditUserForm(obj=user)
        profile_form = UserProfileForm(obj=user.profile)
    else:
        user_form = EditUserForm()
        profile_form = UserProfileForm()

    if user_form.validate_on_submit() and profile_form.validate_on_submit():
        user.name = user_form.name.data
        user.email = user_form.email.data
        user.mobile = user_form.phone.data
        user.address = user_form.address.data
        user.gender = user_form.gender.data

        # ✅ Handle profile picture upload only if a file is selected
        picture_file = profile_form.profile_picture.data
        if picture_file and hasattr(picture_file, 'filename') and picture_file.filename != '':
            filename = secure_filename(picture_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            picture_file.save(filepath)
            user.profile.profile_picture = f"profile_pics/{filename}"

        user.profile.bio = profile_form.bio.data
        user.profile.birth_date = profile_form.birth_date.data

        db.session.commit()
        flash("Profile updated!", "success")
        return redirect(url_for('view_profile'))

    return render_template('edit_profile.html', user_form=user_form, profile_form=profile_form)



@app.route('/book/<int:book_id>', methods=['GET'])
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    reviews = Review.query.filter_by(book_id=book_id).all()

    in_wishlist = False
    if current_user.is_authenticated:
        in_wishlist = Wishlist.query.filter_by(user_id=current_user.id, book_id=book.id).first() is not None

    return render_template('bookstore/book_detail.html', book=book, reviews=reviews, in_wishlist=in_wishlist)





@app.route('/section/<int:section_id>')
def section_page(section_id):
    # Fetch the section details from the database
    section = Section.query.get_or_404(section_id)
    
    # Fetch books that belong to this section (assuming you have a relationship between Section and Book)
    books = Book.query.filter_by(section_id=section.id).all()

    return render_template('bookstore/section.html', section=section, books=books)


# -------------------- Cart Functionality --------------------

@app.route('/cart/add/<int:book_id>', methods=['POST'])
@login_required
def add_to_cart(book_id):
    book = Book.query.get_or_404(book_id)
    cart_item = CartItem.query.filter_by(user_id=current_user.id, book_id=book.id).first()
    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = CartItem(user_id=current_user.id, book_id=book.id, quantity=1)
        db.session.add(cart_item)
    db.session.commit()

    flash(f"✅ '{book.title}' added to your cart.")
    return redirect(url_for('book_detail', book_id=book.id))


@app.route('/cart', methods=['GET'])
@login_required
def view_cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.subtotal for item in cart_items)

    return render_template('bookstore/cart.html', cart_items=cart_items, total=total)


@app.route('/cart/increase/<int:book_id>', methods=['POST'])
@login_required
def increase_quantity(book_id):
    item = CartItem.query.filter_by(user_id=current_user.id, book_id=book_id).first_or_404()
    item.quantity += 1
    db.session.commit()
    return redirect(url_for('view_cart'))


@app.route('/cart/decrease/<int:book_id>', methods=['POST'])
@login_required
def decrease_quantity(book_id):
    item = CartItem.query.filter_by(user_id=current_user.id, book_id=book_id).first_or_404()
    if item.quantity > 1:
        item.quantity -= 1
    else:
        db.session.delete(item)
    db.session.commit()
    return redirect(url_for('view_cart'))


@app.route('/cart/clear', methods=['POST'])
@login_required
def clear_cart():
    CartItem.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash("Your cart has been cleared.")
    return redirect(url_for('view_cart'))


@app.route('/cart/remove/<int:book_id>', methods=['POST'])
@login_required
def remove_from_cart(book_id):
    cart_item = CartItem.query.filter_by(user_id=current_user.id, book_id=book_id).first_or_404()
    db.session.delete(cart_item)
    db.session.commit()
    return redirect(url_for('view_cart'))



# -------------------- Static Pages --------------------

@app.route('/aboutus', methods=['GET'])
@login_required
def aboutus():
    return render_template('bookstore/aboutus.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact_view():
    form = ContactForm()
    if form.validate_on_submit():
        # Create a new contact entry
        new_contact = Contact(
            name=form.name.data,
            email=form.email.data,
            message=form.message.data
        )
        
        # Add to database
        db.session.add(new_contact)
        db.session.commit()
        
        flash("Your message has been sent! We'll get back to you soon.", "success")
        return redirect(url_for('contact_view'))
    
    return render_template('bookstore/contact.html', form=form, success=form.is_submitted() and form.validate())


# -------------------- Order & Checkout --------------------

@app.route('/checkout/shipping', methods=['GET', 'POST'])
@login_required
def shipping_view():
    form = ShippingForm()
    
    if form.validate_on_submit():
        session['shipping_data'] = {
            'name': form.name.data,
            'phone': form.phone.data,
            'email': form.email.data,
            'address': form.address.data,
            'locality': form.locality.data,
            'city': form.city.data,
            'state': form.state.data,
            'pincode': form.pincode.data,
        }
        return redirect(url_for('checkout_view'))
    
    # Pre-fill the form with user data if available
    if request.method == 'GET':
        form.name.data = current_user.name
        form.email.data = current_user.email
        form.phone.data = current_user.mobile
        form.address.data = current_user.address

    return render_template('bookstore/shipping.html', form=form)



@app.route('/checkout', methods=['GET'])
@login_required
def checkout_view():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.subtotal for item in cart_items)

    shipping_data = session.get('shipping_data')
    if not shipping_data:
        flash("Shipping information is missing.")
        return redirect(url_for('shipping_view'))

    return render_template('bookstore/checkout.html', cart_items=cart_items, total_price=total_price, shipping_data=shipping_data)


@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    if 'shipping_data' not in session:
        flash("Shipping data not found.")
        return redirect(url_for('shipping_view'))

    payment_method = request.form.get('payment_method')
    if not payment_method:
        flash("Please select a payment method.")
        return redirect(url_for('checkout_view'))

    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash("Your cart is empty.")
        return redirect(url_for('view_cart'))

    shipping_data = session['shipping_data']
    total = sum(item.subtotal for item in cart_items)

    try:
        order = Order(
            user_id=current_user.id,
            name=shipping_data['name'],
            phone=shipping_data['phone'],
            email=shipping_data['email'],
            address=shipping_data['address'],
            locality=shipping_data['locality'],
            city=shipping_data['city'],
            state=shipping_data['state'],
            pincode=shipping_data['pincode'],
            payment_method=payment_method,
            total_price=total
        )
        db.session.add(order)
        db.session.flush()  # Get the order ID without committing

        for item in cart_items:
            order_item = OrderItem(
                order_id=order.id,
                book_id=item.book_id,
                quantity=item.quantity,
                price=item.book.price
            )
            db.session.add(order_item)
        
        db.session.commit()

        # Clear cart and session data
        CartItem.query.filter_by(user_id=current_user.id).delete()
        session.pop('shipping_data', None)

        flash(f"Order #{order.id} placed successfully!")
        return redirect(url_for('order_success', order_id=order.id))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error placing order: {str(e)}")  # Add proper logging
        flash("An error occurred while placing your order. Please try again.")
        return redirect(url_for('checkout_view'))

@app.route('/order/success/<int:order_id>', methods=['GET'])
@login_required
def order_success(order_id):
    order = Order.query.get_or_404(order_id)
    
    # Check if the order belongs to the current user
    if order.user_id != current_user.id and not current_user.is_admin:
        flash("You don't have permission to view this order.", "danger")
        return redirect(url_for('track_orders'))
        
    return render_template('bookstore/order_success.html', order_id=order.id, name=order.name, total_price=order.total_price)



@app.route('/track_orders')
@login_required
def track_orders():
    # Fetch orders from the database for the current logged-in user
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('bookstore/order_tracking.html', orders=orders)


# -------------------- Client Review --------------------


@app.route('/client_review', methods=['GET', 'POST'])
@login_required
def client_review():
    form = ClientReviewForm()
    
    if request.method == 'POST' and form.validate():
        image_file = form.image.data
        image_filename = None

        if image_file:
            # Ensure the upload directory exists
            upload_folder = os.path.join(app.root_path, 'static/uploads/reviews')
            os.makedirs(upload_folder, exist_ok=True)

            # Secure the filename and save the file
            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(upload_folder, image_filename)
            image_file.save(image_path)

        new_review = ClientReview(
            name=form.name.data,
            image=f'uploads/reviews/{image_filename}' if image_filename else None,
            review=form.review.data,
            rating=form.rating.data
        )

        db.session.add(new_review)
        db.session.commit()
        flash("Your review has been submitted!")
        return redirect(url_for('book_list'))

    return render_template('bookstore/client_review.html', form=form)


# -------------------- Wishlist --------------------

@app.route('/wishlist/add/<int:book_id>', methods=['POST'])
@login_required
def add_to_wishlist(book_id):
    book = Book.query.get_or_404(book_id)
    wishlist_item = Wishlist.query.filter_by(user_id=current_user.id, book_id=book.id).first()

    if not wishlist_item:
        wishlist_item = Wishlist(user_id=current_user.id, book_id=book.id)
        db.session.add(wishlist_item)
        db.session.commit()
        flash(f'"{book.title}" added to your wishlist.')
    else:
        flash(f'"{book.title}" is already in your wishlist.')

    return redirect(url_for('book_detail', book_id=book.id))


@app.route('/wishlist', methods=['GET'])
@login_required
def view_wishlist():
    wishlist_items = Wishlist.query.filter_by(user_id=current_user.id).all()
    return render_template('bookstore/wishlist.html', wishlist_items=wishlist_items)


@app.route('/wishlist/remove/<int:book_id>', methods=['POST'])
@login_required
def remove_from_wishlist(book_id):
    wishlist_item = Wishlist.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if wishlist_item:
        db.session.delete(wishlist_item)
        db.session.commit()
        flash(f'"{wishlist_item.book.title}" removed from your wishlist.')
    return redirect(url_for('view_wishlist'))


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    if query:
        # Search for books in the database
        results = Book.query.filter(Book.title.ilike(f'%{query}%')).all()
    else:
        results = []

    return render_template('bookstore/search_results.html', query=query, results=results)




@app.route('/book/<int:book_id>/review', methods=['GET', 'POST'])
@login_required
def add_review(book_id):
    book = Book.query.get_or_404(book_id)
    form = ReviewForm()

    if form.validate_on_submit():
        review = Review(
            user_id=current_user.id,
            book_id=book.id,
            rating=form.rating.data,
            comment=form.comment.data
        )
        db.session.add(review)
        db.session.commit()
        flash('Review submitted successfully!', 'success')
        return redirect(url_for('book_detail', book_id=book.id))

    # ✅ this part is critical
    return render_template('bookstore/add_review.html', form=form, book=book)





# -------------------- Admin Panel --------------------

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # Check if user is admin
    if not current_user.is_admin:
        flash("You don't have permission to access the admin panel.", "danger")
        return redirect(url_for('dashboard'))
    
    # Dashboard stats
    total_books = Book.query.count()
    total_users = User.query.filter(User.role != 'admin').count()
    total_orders = Order.query.count()
    recent_orders = Order.query.order_by(Order.ordered_date.desc()).limit(5).all()
    
    # Calculate revenue
    revenue = db.session.query(db.func.sum(Order.total_price)).scalar() or 0
    
    return render_template('admin/dashboard.html', 
                          total_books=total_books,
                          total_users=total_users, 
                          total_orders=total_orders,
                          recent_orders=recent_orders,
                          revenue=revenue)



# Book Management
@app.route('/admin/books')
@login_required
def admin_books():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    books = Book.query.all()
    return render_template('admin/books/index.html', books=books)


@csrf.exempt
@app.route('/admin/books/add', methods=['GET', 'POST'])
@login_required
def admin_add_book():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    sections = Section.query.all()
    
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        description = request.form.get('description')
        price = request.form.get('price')
        section_id = request.form.get('section_id')
        cover_image = request.files.get('cover_image')
        
        if not all([title, author, description, price]):
            flash("All fields are required", "danger")
            return redirect(url_for('admin_add_book'))
        
        # Handle image upload
        image_filename = None
        if cover_image and cover_image.filename:
            image_filename = secure_filename(cover_image.filename)
            upload_folder = os.path.join(app.root_path, 'static/uploads/covers')
            os.makedirs(upload_folder, exist_ok=True)
            cover_image.save(os.path.join(upload_folder, image_filename))
            image_filename = f"uploads/covers/{image_filename}"
        
        new_book = Book(
            title=title,
            author=author,
            description=description,
            price=price,
            section_id=section_id if section_id else None,
            cover_image=image_filename
        )
        
        db.session.add(new_book)
        db.session.commit()
        
        flash(f"Book '{title}' has been added successfully!", "success")
        return redirect(url_for('admin_books'))
    
    return render_template('admin/books/add.html', sections=sections)


@csrf.exempt
@app.route('/admin/books/edit/<int:book_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_book(book_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    book = Book.query.get_or_404(book_id)
    sections = Section.query.all()
    
    if request.method == 'POST':
        book.title = request.form.get('title')
        book.author = request.form.get('author')
        book.description = request.form.get('description')
        book.price = request.form.get('price')
        book.section_id = request.form.get('section_id') or None
        
        cover_image = request.files.get('cover_image')
        if cover_image and cover_image.filename:
            image_filename = secure_filename(cover_image.filename)
            upload_folder = os.path.join(app.root_path, 'static/uploads/covers')
            os.makedirs(upload_folder, exist_ok=True)
            cover_image.save(os.path.join(upload_folder, image_filename))
            book.cover_image = f"uploads/covers/{image_filename}"
        
        db.session.commit()
        flash(f"Book '{book.title}' has been updated!", "success")
        return redirect(url_for('admin_books'))
    
    return render_template('admin/books/edit.html', book=book, sections=sections)


@csrf.exempt
@app.route('/admin/books/delete/<int:book_id>', methods=['POST'])
@login_required
def admin_delete_book(book_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    book = Book.query.get_or_404(book_id)
    title = book.title
    
    # Delete book
    db.session.delete(book)
    db.session.commit()
    
    flash(f"Book '{title}' has been deleted!", "success")
    return redirect(url_for('admin_books'))

# Section Management

@csrf.exempt
@app.route('/admin/sections')
@login_required
def admin_sections():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    sections = Section.query.all()
    return render_template('admin/sections/index.html', sections=sections)


@csrf.exempt
@app.route('/admin/sections/add', methods=['GET', 'POST'])
@login_required
def admin_add_section():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        banner = request.files.get('banner')
        
        if not name:
            flash("Section name is required", "danger")
            return redirect(url_for('admin_add_section'))
        
        # Handle banner upload
        banner_filename = None
        if banner and banner.filename:
            banner_filename = secure_filename(banner.filename)
            upload_folder = os.path.join(app.root_path, 'static/uploads/banners')
            os.makedirs(upload_folder, exist_ok=True)
            banner.save(os.path.join(upload_folder, banner_filename))
            banner_filename = f"uploads/banners/{banner_filename}"
        
        new_section = Section(
            name=name,
            description=description,
            banner=banner_filename
        )
        
        db.session.add(new_section)
        db.session.commit()
        
        flash(f"Section '{name}' has been added!", "success")
        return redirect(url_for('admin_sections'))
    
    return render_template('admin/sections/add.html')



@csrf.exempt
@app.route('/admin/sections/edit/<int:section_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_section(section_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    section = Section.query.get_or_404(section_id)
    
    if request.method == 'POST':
        section.name = request.form.get('name')
        section.description = request.form.get('description')
        
        banner = request.files.get('banner')
        if banner and banner.filename:
            banner_filename = secure_filename(banner.filename)
            upload_folder = os.path.join(app.root_path, 'static/uploads/banners')
            os.makedirs(upload_folder, exist_ok=True)
            banner.save(os.path.join(upload_folder, banner_filename))
            section.banner = f"uploads/banners/{banner_filename}"
        
        db.session.commit()
        flash(f"Section '{section.name}' has been updated!", "success")
        return redirect(url_for('admin_sections'))
    
    return render_template('admin/sections/edit.html', section=section)



@csrf.exempt
@app.route('/admin/sections/delete/<int:section_id>', methods=['POST'])
@login_required
def admin_delete_section(section_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    section = Section.query.get_or_404(section_id)
    name = section.name
    
    # Check if section has books
    if Book.query.filter_by(section_id=section_id).first():
        flash(f"Cannot delete section '{name}' because it contains books. Please move or delete the books first.", "danger")
        return redirect(url_for('admin_sections'))
    
    # Delete section
    db.session.delete(section)
    db.session.commit()
    
    flash(f"Section '{name}' has been deleted!", "success")
    return redirect(url_for('admin_sections'))



@csrf.exempt
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin/users/index.html', users=users)



@csrf.exempt
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.mobile = request.form.get('mobile')
        user.address = request.form.get('address')
        user.gender = request.form.get('gender')
        user.role = request.form.get('role')
        
        db.session.commit()
        flash(f"User '{user.name}' has been updated!", "success")
        return redirect(url_for('admin_users'))
    
    return render_template('admin/users/edit.html', user=user)

@csrf.exempt
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    # Admin can't delete themselves
    if user_id == current_user.id:
        flash("You cannot delete your own account!", "danger")
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    name = user.name
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User '{name}' has been deleted!", "success")
    return redirect(url_for('admin_users'))


# -------------------- Add this route to your app.py file --------------------


@csrf.exempt
@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def admin_add_user():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        address = request.form.get('address')
        gender = request.form.get('gender')
        role = request.form.get('role')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not all([name, email, mobile, password, confirm_password]):
            flash("All required fields must be filled", "danger")
            return redirect(url_for('admin_add_user'))
        
        # Check if passwords match
        if password != confirm_password:
            flash("Passwords don't match", "danger")
            return redirect(url_for('admin_add_user'))
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already exists", "danger")
            return redirect(url_for('admin_add_user'))
        
        # Create new user
        new_user = User(
            name=name,
            email=email,
            mobile=mobile,
            address=address,
            gender=gender,
            role=role
        )
        new_user.set_password(password)
        
        # Create user profile
        db.session.add(new_user)
        db.session.flush()  # Get user ID without committing
        
        profile = UserProfile(user_id=new_user.id)
        db.session.add(profile)
        
        db.session.commit()
        
        flash(f"User '{name}' has been added successfully!", "success")
        return redirect(url_for('admin_users'))
    
    return render_template('admin/users/add.html')



# Order Management


@csrf.exempt
@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    orders = Order.query.order_by(Order.ordered_date.desc()).all()
    return render_template('admin/orders/index.html', orders=orders)


@csrf.exempt
@app.route('/admin/orders/<int:order_id>')
@login_required
def admin_order_detail(order_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    order = Order.query.get_or_404(order_id)
    return render_template('admin/orders/detail.html', order=order)


@csrf.exempt
@app.route('/admin/orders/update-status/<int:order_id>', methods=['POST'])
@login_required
def admin_update_order_status(order_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    order = Order.query.get_or_404(order_id)
    order.order_status = request.form.get('order_status')
    order.payment_status = request.form.get('payment_status')
    
    db.session.commit()
    flash(f"Order #{order.id} status updated!", "success")
    return redirect(url_for('admin_order_detail', order_id=order.id))



@csrf.exempt
@app.route('/admin/reviews')
@login_required
def admin_reviews():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    # Book reviews
    book_reviews = Review.query.order_by(Review.created_at.desc()).all()
    
    # Client reviews
    client_reviews = ClientReview.query.order_by(ClientReview.created_at.desc()).all()
    
    return render_template('admin/reviews/index.html', 
                          book_reviews=book_reviews,
                          client_reviews=client_reviews)



@csrf.exempt
@app.route('/admin/reviews/delete/<string:review_type>/<int:review_id>', methods=['POST'])
@login_required
def admin_delete_review(review_type, review_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    if review_type == 'book':
        review = Review.query.get_or_404(review_id)
    elif review_type == 'client':
        review = ClientReview.query.get_or_404(review_id)
    else:
        flash("Invalid review type.", "danger")
        return redirect(url_for('admin_reviews'))
    
    db.session.delete(review)
    db.session.commit()
    
    flash("Review has been deleted!", "success")
    return redirect(url_for('admin_reviews'))



@csrf.exempt
@app.route('/admin/contacts')
@login_required
def admin_contacts():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    # Get all contact submissions
    contacts = Contact.query.order_by(Contact.id.desc()).all()
    return render_template('admin/contacts/index.html', contacts=contacts)



@csrf.exempt
@app.route('/admin/contacts/view/<int:contact_id>')
@login_required
def admin_view_contact(contact_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    contact = Contact.query.get_or_404(contact_id)
    return render_template('admin/contacts/view.html', contact=contact)



@csrf.exempt
@app.route('/admin/contacts/delete/<int:contact_id>', methods=['POST'])
@login_required
def admin_delete_contact(contact_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    contact = Contact.query.get_or_404(contact_id)
    
    db.session.delete(contact)
    db.session.commit()
    
    flash("Contact message has been deleted!", "success")
    return redirect(url_for('admin_contacts'))


# -------------------- Admin Wishlist Management --------------------
@csrf.exempt
@app.route('/admin/wishlists')
@login_required
def admin_wishlists():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    # Get all wishlist items with user and book information
    wishlist_items = Wishlist.query.all()
    
    # Group wishlist items by user
    users_wishlists = {}
    for item in wishlist_items:
        if item.user.id not in users_wishlists:
            users_wishlists[item.user.id] = {
                'user': item.user,
                'items': []
            }
        users_wishlists[item.user.id]['items'].append(item)
    
    return render_template('admin/wishlists/index.html', users_wishlists=users_wishlists)
@csrf.exempt
@app.route('/admin/wishlists/<int:user_id>')
@login_required
def admin_user_wishlist(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    wishlist_items = Wishlist.query.filter_by(user_id=user_id).all()
    
    return render_template('admin/wishlists/user_wishlist.html', user=user, wishlist_items=wishlist_items)


@csrf.exempt
@app.route('/admin/wishlists/delete/<int:wishlist_id>', methods=['POST'])
@login_required
def admin_delete_wishlist_item(wishlist_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    wishlist_item = Wishlist.query.get_or_404(wishlist_id)
    user_id = wishlist_item.user_id
    book_title = wishlist_item.book.title
    
    db.session.delete(wishlist_item)
    db.session.commit()
    
    flash(f"Removed '{book_title}' from user's wishlist.", "success")
    return redirect(url_for('admin_user_wishlist', user_id=user_id))



@csrf.exempt
@app.route('/admin/wishlists/clear/<int:user_id>', methods=['POST'])
@login_required
def admin_clear_user_wishlist(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    Wishlist.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    
    flash(f"Cleared all items from {user.name}'s wishlist.", "success")
    return redirect(url_for('admin_wishlists'))



if __name__ == "__main__":
    app.run(debug=True)
