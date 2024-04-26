from datetime import date
import os
#import psycopg2
# this is for admin-only decorator:
from functools import wraps
# added import of 'session' to use to clear session if creating new database
from flask import Flask, abort, render_template, redirect, url_for, flash, request,Response,session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
# create_engine, inspect, and text are for the code that checks whether a postgresql db exists and
# to initialize the database if not. OperationalError is also needed for this.
from sqlalchemy import Integer, String, Text, select, ForeignKey, create_engine, inspect,text
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
# substitute for Gravatar library, since Gravitar does not yet support flask 3.00:
import hashlib

# render.com env var version of FLASK_KEY: SHo9nhBXox7C0sKR68BYkfBA6O6donzW

# create blogsite repo, then locally run these cmds:
# git remote add origin https://github.com/meqaniqal/blogsite.git
# git branch -M main
# git push -u origin main
# to remove files/folders I forgot to add to .gitignore until after commit:
# git rm --cached -r <file or folder name>, for each file/folder I want to remove from the repo
# --cached means to remove from the index that will tell what to have on the remote, but not to remove
# the file from the local git
# commit the file and push it.

# to serve the app from main.py, make a Procfile that contains: web: gunicorn main:appgit

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
print(app.config['SECRET_KEY'])
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)



def gravatar_url(email, size=100, rating='g', default='retro', force_default=False):
    hash_value = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_value}?s={size}&d={default}&r={rating}&f={force_default}"

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

# set absolute directory for the database
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
# Create the 'instance' directory if it doesn't exist
os.makedirs(instance_path, exist_ok=True)
db_path = os.path.join(instance_path, 'posts.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+db_path

# this is so render.com can use a postgresql URI instead of
env_db_uri=os.environ.get('DB_URI')
if env_db_uri:
    app.config['SQLALCHEMY_DATABASE_URI'] =env_db_uri
    print('using env var for db:',env_db_uri)


# the following line can break if switching between run configurations in pycharm, so the above lines
# set the uri to the absolute path of the instance folder.
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'

db = SQLAlchemy(model_class=Base)

# Create a database engine using the database URI
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])

# Get the database name from the URI
database_name = app.config['SQLALCHEMY_DATABASE_URI'].split('/')[-1]
print('database_name:',database_name)

# Check if the database exists
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
    # For SQLite databases, check if the file exists
    database_exists = os.path.isfile(database_name)
else:
    # For other databases (e.g., PostgreSQL), use the inspect function
    inspector = inspect(engine)
    database_exists = database_name in inspector.get_schema_names()


if database_exists:
    print(f"Database {database_name} already exists.")
else:
    try:
        # Create the database
        conn = engine.connect()
        conn.execute(text(f"CREATE DATABASE {database_name};"))
        conn.close()
        print(f"Database {database_name} created successfully.")
    except OperationalError as e:
        print(f"Error creating the database {database_name}:", e)

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

def print_users():
    users = db.session.query(User).all()
    print(users)
    for user in users:
         print('userid:',user.id,'email:',user.email)


with app.app_context():

    # uncomment on first run to create the database and an admin user
    first_user_email=os.environ.get('FIRST_USER_EMAIL')
    first_user_password=os.environ.get('FIRST_USER_PASSWORD')
    # if not supplied by environment, create an easy to remember admin user
    if not first_user_email or not first_user_password:
        first_user_email="admin@example.com"
        first_user_password="1234"
    # Get the database file path
    database_path = os.path.join(app.instance_path, 'posts.db')
    print('database_path:',database_path)
    # Check if the file exists
    # database_exists = os.path.exists(database_path)
    # print('database exists?',database_exists)
    if not database_exists:
        db.create_all()
        admin_user=User(email=first_user_email,
                        password=generate_password_hash(first_user_password,method='pbkdf2:sha256', salt_length=8),
                        name="admin")
        db.session.add(admin_user)
        db.session.commit()
        print_users()


@login_manager.user_loader
def load_user(user_id):
    print('in load_user. User_id:',user_id)
    # if user_id hasn't been reset upon a database reset, this will detect that and remove
    user=db.session.get(User, user_id)
    print('User with that id:',user)
    if user==None:
        # Clear the user's session data
        session.clear()
        return None
    return db.get_or_404(User, user_id)




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
    form = LoginForm()
    if email:
        form = LoginForm(email=email)

    if form.validate_on_submit():
        email = request.form.get('email')
        print('In login, users found:')
        print_users()
        print('email entered from form:',email)
        # this with block is to keep the session from being wiped when using db.session.execute.
        with db.session.no_autoflush:
            user = db.session.scalar(select(User).where(User.email == email))
            #user = db.session.execute(select(User).where(User.email == email)).scalar()
        print('user searched for in db:')
        print('email',user.email,'id:',user.id)
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

# Create an admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function

# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
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
