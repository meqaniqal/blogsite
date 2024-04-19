from datetime import date
from typing import List

from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
#from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, select, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# substitute for Gravatar library, since Gravitar does not yet support flask 3.00:
import hashlib

def gravatar_url(email, size=100, rating='g', default='retro', force_default=False):
    hash_value = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_value}?s={size}&d={default}&r={rating}&f={force_default}"

# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)

"""# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments=relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Foreign Key("users.id") refers to the "users" tablename
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author: Mapped["User"] = relationship(back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments=relationship("Comment", back_populates="parent_post")



class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    comment_author:Mapped["User"]=relationship(back_populates="comments")
    # child relationship:
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_post=relationship("BlogPost",back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)"""

with app.app_context():
    db.create_all()
    """admin_user=User(email="admin@example.com",
                    password=generate_password_hash("1234",method='pbkdf2:sha256', salt_length=8),
                    name="admin")
    db.session.add(admin_user)
    db.session.commit()"""

#cmd-opt-R does hard refresh to hopefully reset user_id
@login_manager.user_loader
def load_user(user_id):
    print(f"user_id:{user_id}")
    #logout_user()
    # If due to deleting or switching out db, user_id printed above is stuck on whatever the browser
    # remembers last, you can replace user_id below with the user id you want the page to assume
    # you can use db editor to switch user ids to move the user whose password you know to admin user.
    #return None
    return db.get_or_404(User, user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'GET'])
def register():
    logout_user()
    form = RegisterForm()
    if form.validate_on_submit():
        name = request.form.get('name')
        email = request.form.get('email')
        email_exists = db.session.execute(select(User).where(User.email == email)).scalar()
        if email_exists:
            print(form.data)
            flash(f'User already registered. Login with email: {email}', 'User already registered')
            return redirect(url_for('login', email=email))
        password = request.form.get('password')
        pwd_hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        print(name, email, password, pwd_hashed)
        new_user = User(name=name, email=email, password=pwd_hashed)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    logout_user()
    email = request.args.get('email')
    print('In login. value of form before making a blank form:', email)
    form = LoginForm()
    if email:
        form = LoginForm(email=email)

    if form.validate_on_submit():
        email = request.form.get('email')
        user = db.session.execute(select(User).where(User.email == email)).scalar()

        if user is None:
            flash('User not found', 'error')
            return redirect(url_for('login', form=form))
        password = request.form.get('password')
        pwhash = user.password

        pwd_correct = check_password_hash(pwhash, password)
        if not pwd_correct:
            flash('Password incorrect', 'error')
            return redirect(url_for('login', form=form))
        login_user(user, remember=True)

        flash('Login Successful', 'success')
        return redirect(url_for('get_all_posts', user_id=current_user.id))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    # current_user is automatically accessible in templates, so look in the template for the code that tests the
    # user id to see if it is 1, which is the first registered user,
    # which we have decided to specify as having special priveleges
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        # go to login if not logged in:
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        comment=Comment(comment_author=current_user,parent_post=requested_post,text=form.comment.data)

        db.session.add(comment)
        db.session.commit()
    # compile a list (set) of unique commenters to get gravatar images for
    commenter_set=set()
    for comment_i in requested_post.comments:
        author=comment_i.comment_author
        commenter_set.add((author.name,author.email))
    # create a dict of commenter usernames and a gravatar logo based on their email:
    commenters={item[0]: gravatar_url(item[1]) for item in commenter_set}
    print("commenters",commenters)

    return render_template("post.html", post=requested_post, form=form,gravatars=commenters)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":

    app.run(debug=True, port=5002)
