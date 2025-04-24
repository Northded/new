import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SelectField, validators
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, Regexp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://flask:1234@localhost/myflaskdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)

class User(db.Model, UserMixin):
    __tablename__ = 'users'  
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    last_name = db.Column(db.String(50))
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    role = db.relationship('Role', backref='users')
    
    def set_password(self, password):
            self.password_hash = generate_password_hash(
                password,
                method='pbkdf2:sha256',  
                salt_length=16
            )
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Forms
class UserForm(FlaskForm):
    login = StringField('Логин', validators=[
        DataRequired(message="Логин обязателен для заполнения"),
        Length(min=5, max=20, message="Логин должен быть от 5 до 20 символов"),
        Regexp(r'^[A-Za-z0-9]+$', message="Только латинские буквы и цифры")
    ])

    password = PasswordField('Пароль', validators=[
        DataRequired(message="Пароль обязателен для заполнения")
    ])

    first_name = StringField('Имя', validators=[
        DataRequired(message="Имя обязательно для заполнения"),
        Length(max=50, message="Максимум 50 символов")
    ])

    last_name = StringField('Фамилия', validators=[
        Length(max=50, message="Максимум 50 символов")
    ])

    middle_name = StringField('Отчество', validators=[
        Length(max=50, message="Максимум 50 символов")
    ])

    role_id = SelectField('Роль', coerce=int, validators=[
        DataRequired(message="Выберите роль пользователя")
    ])

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Старый пароль', [validators.InputRequired()])
    new_password = PasswordField('Новый пароль', [validators.InputRequired()])
    confirm_password = PasswordField('Подтвердите пароль', [validators.InputRequired()])

# Helpers
def validate_password(password):
    errors = []
    if len(password) < 8 or len(password) > 128:
        errors.append("Длина должна быть 8-128 символов")
    if not re.search(r'[A-ZА-Я]', password):
        errors.append("Нужна минимум 1 заглавная буква")
    if not re.search(r'[a-zа-я]', password):
        errors.append("Нужна минимум 1 строчная буква")
    if not re.search(r'\d', password):
        errors.append("Нужна минимум 1 цифра")
    if re.search(r'\s', password):
        errors.append("Не должно быть пробелов")
    if not re.fullmatch(r'[A-Za-zА-Яа-я0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'.,:;]+', password):
        errors.append("Недопустимые символы")
    return errors

# Routes
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(login=request.form['login']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверные учетные данные', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    form = UserForm()
    form.role_id.choices = [(r.id, r.name) for r in Role.query.all()]
    
    if form.validate_on_submit():
        try:
            # Создание пользователя
            new_user = User(
                login=form.login.data,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                middle_name=form.middle_name.data,
                role_id=form.role_id.data
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь создан успешно!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка создания пользователя: {str(e)}', 'danger')
    
    # Передаем флаг отправки формы в шаблон
    return render_template(
        'user_form.html',
        form=form,
        user=None,
        form_submitted=request.method == 'POST'
    )

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    # Удаляем поля логин и пароль из формы
    del form.login
    del form.password
    form.role_id.choices = [(r.id, r.name) for r in Role.query.all()]
    
    if form.validate_on_submit():
        try:
            # Обновляем данные
            user.first_name = form.first_name.data
            user.last_name = form.last_name.data
            user.middle_name = form.middle_name.data
            user.role_id = form.role_id.data
            
            db.session.commit()
            flash('Данные пользователя обновлены', 'success')
            return redirect(url_for('view_user', user_id=user.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка обновления: {str(e)}', 'danger')
    
    return render_template('user_form.html', form=form, user=user)

@app.route('/users/<int:user_id>')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('Пользователь успешно удален', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Проверка старого пароля
        if not current_user.check_password(form.old_password.data):
            flash('Неверный текущий пароль', 'danger')
            return redirect(url_for('change_password'))
        
        # Проверка совпадения новых паролей
        if form.new_password.data != form.confirm_password.data:
            flash('Новые пароли не совпадают', 'danger')
            return redirect(url_for('change_password'))
        
        # Валидация нового пароля
        errors = validate_password(form.new_password.data)
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('change_password'))
        
        try:
            # Обновление пароля
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Пароль успешно изменен', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при изменении пароля: {str(e)}', 'danger')
    
    return render_template('change_password.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)