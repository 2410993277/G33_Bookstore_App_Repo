README.txt
==========

Description:
------------
This project demonstrates a hybrid web application architecture where **Flask acts as a RESTful API provider**, and **Django functions as the frontend and API consumer**. It simulates a fully functional Online Bookstore system, with features such as browsing books by section, submitting client reviews, and sending messages via contact forms.

The architecture is split into two parts:

1. Django-Based Bookstore Frontend  
2. Flask-Based RESTful API Backend (for Books, Sections, Contact Us, and Client Reviews)

Project Structure:
------------------
1. *Flask App (API Provider)*  
   - Exposes APIs for:
     - Books
     - Sections (Categories)
     - Contact Us Form
     - Client Reviews
   - Built with Flask, Flask-RESTful, and SQLAlchemy
   - Acts as a lightweight microservice sending JSON responses to Django

2. *Django App (API Consumer + Frontend)*  
   - Uses `requests` to call Flask API endpoints
   - Handles user authentication, cart/checkout, reviews, and admin panel
   - Renders HTML templates using Django views

Usage Instructions:
-------------------
1. *Setup Flask API Server:*
   - Navigate to the Flask project directory
   - Create a virtual environment and install dependencies:
     
     pip install -r requirements.txt
     
   - Initialize the database and create an admin user (via shell):

     python  
     >>> from app import db, bcrypt  
     >>> from models import User  
     >>> pw = bcrypt.generate_password_hash("admin123").decode('utf-8')  
     >>> admin = User(name="Admin", email="admin@gmail.com", mobile="1234567890", role="admin", password=pw, is_admin=True)  
     >>> db.session.add(admin)  
     >>> db.session.commit()  
     >>> exit()

   - Start the Flask server:

     python app.py

   - API will be available at: http://localhost:5000/

2. *Setup Django Frontend Project:*
   - Navigate to the Django project directory
   - Create a virtual environment and install dependencies:
     
     pip install -r requirements.txt
     
   - Run migrations and create a Django superuser:

     python manage.py migrate  
     python manage.py createsuperuser

   - Start the Django server:

     python manage.py runserver

   - Access frontend at: http://localhost:8000/

3. *Communication Flow:*
   - Django sends HTTP requests to Flask endpoints to:
     - Retrieve book and section data
     - Fetch and submit client reviews
     - Submit contact form messages
   - Flask returns JSON, which Django renders in its views

Key Django Functionalities:
---------------------------
- Book Browsing and Search by Section (via Flask API)
- Cart and Multi-Step Checkout System
- Review Submission and Display (via Flask API)
- Contact Us Form Handling (via Flask API)
- User Registration, Login, and Profile View
- Django Admin Panel for internal data management

Flask API Endpoints:
--------------------
- `GET /api/books`: Retrieve book data
- `GET /api/sections`: Retrieve all categories/sections
- `POST /api/contact`: Submit contact message
- `GET /api/reviews`: Fetch client reviews
- `POST /api/reviews`: Submit a review

Dependencies:
-------------
- Python 3.8+
- Django
- Flask
- Flask-RESTful
- Flask-Bcrypt
- Flask-SQLAlchemy
- requests
