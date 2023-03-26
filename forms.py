from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class CreateRegisterForm(FlaskForm):
    email = StringField("Email :", validators=[DataRequired()])
    password = PasswordField("Password :", validators=[DataRequired()])
    name = StringField("Name :", validators=[DataRequired()])
    submit = SubmitField()


class CreateLoginForm(FlaskForm):
    email = StringField("Email :", validators=[DataRequired()])
    password = PasswordField("Password :", validators=[DataRequired()])
    submit = SubmitField()


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Command :", validators=[DataRequired()])
    submit = SubmitField(label="Submit command")