
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField, FileField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Email, Length
from flask_wtf.file import FileAllowed


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField('Send Message')

class ClientReviewForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    review = TextAreaField('Review', validators=[DataRequired()])
    rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=5)])



class ReviewForm(FlaskForm):
    rating = IntegerField('Rating (1 to 5)', validators=[DataRequired(), NumberRange(min=1, max=5)])
    comment = TextAreaField('Comment', validators=[DataRequired(), Length(min=5, max=1000)])
    submit = SubmitField('Submit Review')