from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    # id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    # subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    # date: Mapped[str] = mapped_column(String(250), nullable=False)
    # body: Mapped[str] = mapped_column(Text, nullable=False)
    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    # img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    id = mapped_column(Integer, primary_key=True)
    title = mapped_column(String(250), unique=True, nullable=False)
    subtitle = mapped_column(String(250), nullable=False)
    date = mapped_column(String(250), nullable=False)
    body = mapped_column(Text, nullable=False)
    # author = mapped_column(String(250), nullable=False)
    img_url = mapped_column(String(250), nullable=False)
    author_id = mapped_column(ForeignKey("users.id"))  # table name, not class
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")


# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    # id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # name: Mapped[str] = mapped_column(String(250), nullable=False)
    # email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    # password: Mapped[str] = mapped_column(String(100), nullable=False)
    id = mapped_column(Integer, primary_key=True)
    name = mapped_column(String(250), nullable=False)
    email = mapped_column(String(100), unique=True, nullable=False)
    password = mapped_column(String(100), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class Comment(db.Model):
    id = mapped_column(Integer, primary_key=True)
    text = mapped_column(Text, nullable=False)
    author_id = mapped_column(ForeignKey("users.id"))  # table name, not class
    author = relationship("User", back_populates="comments")
    post_id = mapped_column(ForeignKey("blog_posts.id"))  # table name, not class
    post = relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() != "1":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if user with this e-mail already exists
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if user is not None:
            flash(f"User {form.email.data} already exists, please login.")
            return render_template("login.html", form=LoginForm())
        new_user_password = form.password.data
        hash_pwd = generate_password_hash(new_user_password, method='pbkdf2', salt_length=8)
        new_user = User(name=form.name.data, password=hash_pwd, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)  # flask_login method, so it can proceed where "login is required" and be traced
        return redirect(url_for('get_all_posts'))  # home
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if user is None:
            flash(f"User {form.email.data} doesn't exist, please register or login as different user.")
            return redirect(url_for('login'))
        if not check_password_hash(pwhash=user.password, password=form.password.data):
            flash("Login unsuccessful, please register or try again.")
            return redirect(url_for('login'))
        login_user(user)  # flask_login method, so it can proceed where "login is required" and be traced
        return redirect(url_for('get_all_posts'))  # home
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
# @login_required - this would restrict not commenting but viewing a post only to logged-in users.
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:  # can't comment
            flash("Please login or register.")
            return redirect(url_for('login'))
        db.session.add(Comment(text=form.body.data, author_id=current_user.get_id(), post_id=post_id))
        db.session.commit()
    comments = db.session.execute(db.select(Comment).where(Comment.post_id == post_id)).scalars().all()
    return render_template("post.html", post=requested_post, form=form, comments=comments)


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
@admin_only
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
@admin_only
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
