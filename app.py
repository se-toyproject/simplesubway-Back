from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# SQLite 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # 세션 관리를 위한 secret key 설정

db = SQLAlchemy(app)

# 사용자 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# 데이터베이스 초기화
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('search'))
    else:
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        # 이메일로 사용자 검색
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return jsonify({'error': 'User already exists!'}), 400

        # 비밀번호 해싱
        hashed_password = generate_password_hash(password, method='sha256')

        # 새로운 사용자 생성
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully!'}), 201

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # 이메일과 비밀번호로 사용자 검색
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # 세션에 사용자 ID 저장
            session['username'] = user.username  # 세션에 사용자 이름 저장
            return redirect(url_for('search'))  # 로그인 후 리디렉션할 페이지
        else:
            return render_template('login.html', error="Invalid credentials")  # 로그인 실패 시 오류 메시지

    return render_template('login.html')

@app.route('/favorites')
def favorites():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('favorites.html')

@app.route('/results')
def results():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('results.html')

@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('search.html')

@app.route('/logout')
def logout():
    session.clear()  # 세션 정보를 삭제
    return redirect(url_for('login'))  # 로그인 페이지로 리디렉션

if __name__ == '__main__':
    app.run(debug=True)
