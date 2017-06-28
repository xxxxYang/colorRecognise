import os
from PIL import Image
from .. import db
from ..models import Post, Comment, User
import daltonize
from flask import render_template, redirect, request, url_for
from . import main
from werkzeug.utils import secure_filename
from flask_login import current_user
from .forms import CommentForm


dir = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(dir, '../static/user_upload/')
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def image_transfer(filepath):
    orig_img = Image.open(filepath)
    filename = os.path.basename(filepath)
    # print 'filename:' + filename
    dirname = os.path.dirname(filepath)
    # print 'dirname:' + dirname
    dalton_rpg = daltonize.daltonize(orig_img, 'd')
    dalton_img = daltonize.array_to_img(dalton_rpg)
    dalton_img.save(dirname + '/deuteronopia_' + filename)
    dalton_rgb = daltonize.daltonize(orig_img, 'p')
    dalton_img = daltonize.array_to_img(dalton_rgb)
    dalton_img.save(dirname + '/protonapia_' + filename)
    dalton_rgb = daltonize.daltonize(orig_img, 't')
    dalton_img = daltonize.array_to_img(dalton_rgb)
    dalton_img.save(dirname + '/tritanopia_' + filename)


@main.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@main.route('/forum')
def forum():
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=12, error_out=True)
    posts = pagination.items
    return render_template('forum.html', count=10, posts=posts)


@main.route('/converter', methods=['GET', 'POST'])
def converter():
    # print 'request.files:', request.files
    # print 'request.headers:', request.headers
    if request.method == 'POST':
        if 'file' not in request.files:
            print 'No file part'
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            print 'No selected file'
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filesavepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filesavepath)
            image_transfer(filesavepath)
            # print 'before redirect'
            return redirect(url_for('main.uploaded_file', filename=filename))
    return render_template('converter.html')


@main.route('/converter/<filename>', methods=['GET', 'POST'])
def uploaded_file(filename):
        result_file_name = filename
        return render_template('converter.html', show_result=True,
                               result_file_name=result_file_name)


@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    views = post.views + 1
    post.views = views
    db.session.add(post)
    if request.method == 'POST':
        content = request.form.get('comment', None)
        print "comment:" + content
        comment = Comment(body=content,
                          post=post,
                          author=current_user._get_current_object())
        db.session.add(comment)
        return redirect(url_for('.post', id=post.id))

    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          author=current_user._get_current_object())
        db.session.add(comment)
        return redirect(url_for('.post', id=post.id))
    return render_template('blog.html', post=post, form=form)


@main.route('/profile/<int:id>', methods=['GET', 'POST'])
def profile(id):
    user = User.query.get_or_404(id)
    return render_template('profile.html', user=user)
