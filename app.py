from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
app = Flask(__name__)

import requests
from bs4 import BeautifulSoup

from pymongo import MongoClient
import certifi

ca = certifi.where()
client = MongoClient('mongodb+srv://sparta:test@cluster0.ervhju3.mongodb.net/?retryWrites=true&w=majority', tlsCAFile=ca)
db = client.dbsparta

# JWT 토큰을 만들 때 필요한 비밀문자열입니다. 아무거나 입력해도 괜찮습니다.
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 할 수 있습니다.
SECRET_KEY = 'SPARTA'

# JWT 패키지를 사용합니다. (설치해야할 패키지 이름: pyjwt)
import jwt

# 토큰에 만료시간을 줘야하기 때문에, datetime 모듈도 사용합니다.
import datetime

# 회원가입 시엔, 비밀번호를 암호화하여 DB에 저장해두는 게 좋습니다.
# 그렇지 않으면, 개발자(=나)가 회원들의 비밀번호를 볼 수 있으니까요.^^;
import hashlib

@app.route('/')
def home():
    return render_template('index.html')

# 회원 가입 페이지 표시
@app.route('/register')
def register():
    return render_template('register.html')

# 로그인 페이지 호출
@app.route('/login')
def login():
    return render_template('login.html')

# [회원가입 API]
# id, pw, nickname을 받아서, mongoDB에 저장합니다.
# 저장하기 전에, pw를 sha256 방법(=단방향 암호화. 풀어볼 수 없음)으로 암호화해서 저장합니다.
@app.route('/api/register', methods=['POST'])
def api_register():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    nickname_receive = request.form['nickname_give']
    retype_pw_receive = request.form['retype_pw_give']

    if not id_receive or not pw_receive or not nickname_receive or not retype_pw_receive :
        # 필수 입력 항목이 비어 있는지 확인하고, 하나라도 비어 있다면 오류 메시지를 반환함
        return jsonify({'result': '입력되지 않은 값이 있습니다.'})
    
    # if pw_receive != retype_pw_receive:
    #     # 입력받은 비밀번호가 일치하는지 하고 일치하지 않으면 오류 메세지를 반환함
    #     # 클라이언트에서 처리할 수 있음 -> js로 구현하여 api 요청하는 횟수를 줄이도록 개선 할 것. 
    #     return jsonify({'result': '비밀번호가 일치하지 않습니다.'})
    
    # 입력받은 사용자 ID가 이미 사용 중인지 확인
    if db.user.find_one({'$or': [{'id': id_receive}, {'nick': nickname_receive}]}):
        return jsonify({'result': '이미 사용 중인 아이디 또는 닉네임입니다.'})

    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest() # 비밀번호를 해싱하여 보안 강화

    # 사용자 ID가 사용 가능하면, 사용자 정보를 데이터베이스에 저장함
    db.user.insert_one({'id': id_receive, 'pw': pw_hash, 'nick': nickname_receive})

    return jsonify({'result': 'success'}) #성공 메세지 반환

#김보슬 작성
    # [로그인 API]
    # id, pw를 받아서, DB에서 조회 후, 맞으면 JWT token을 생성하여 반환합니다.
    # 만약, 조회된 사용자 정보가 없으면, 오류 메시지를 반환합니다.
@app.route('/api/login', methods=['POST'])
def api_login():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    nickname_receive = request.form['nickname_give']
    
    if id_receive == "" or pw_receive == "" or nickname_receive =="":
            # 필수 입력 항목이 비어 있는지 확인하고, 하나라도 비어 있다면 오류 메시지를 반환함
        return jsonify({'msg': 'error : 입력되지 않은 값이 있습니다.'})

    user = db.user.find_one({'id': id_receive})
    
    if not user:
    # 사용자 정보가 없으면, 오류 메시지를 반환함
        return jsonify({'msg': 'error : 일치하는 사용자 정보가 없습니다.'})
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest() # 입력받은 비밀번호를 해싱하여 비교함
    if pw_hash != user['pw']:
    # 비밀번호가 일치하지 않으면, 오류 메시지를 반환함
        return jsonify({'msg': 'error : 비밀번호가 일치하지 않습니다.'})

# JWT 토큰 생성
    payload = {
    'user_id': str(user['_id']),  # MongoDB document ID를 문자열로 변환하여 사용
    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # 30분 후 만료
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')

    return jsonify({'result': 'success', 'token': token})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)#로그인 
@app.route("/")
def home():
    if "userId" in session:
        return render_template("login.html", nickname = session.get("userId"), login = True)
    else: 
        return render_template("login.html", login = False)
    
#이제 "/login" 경로는 GET 요청 대신 POST 요청을 수신하고 사용자 이름과 암호가 유효한 경우 인코딩된 토큰이 포함된 JSON 응답을 반환합니다.
@app.route("/login", methods=["POST"])
def login():
    global ID, PW
    _id_ = request.form.get("loginId")
    _password_ = request.form.get("loginPw")


# 토큰에는 사용자 ID와 현재 시간으로부터 30분의 만료 시간이 포함됩니다.
    if ID == _id_ and PW == _password_:
        token = jwt.encode({"userId": _id_, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.secret_key)
        session["token"] = token
        return jsonify({"token": token.decode("UTF-8")})
    else:
        return jsonify({"error": "Invalid username or password"}), 401

#"/logout" 경로는 이제 세션에서 "userId" 대신 "token" 키를 제거합니다.
@app.route("/logout")
def logout():
    session.pop("token", None)
    return redirect(url_for("login"))

#인증이 필요한 보호 자원의 예로 "/protected" 경로가 추가되었습니다.
@app.route("/protected")
def protected():
    token = session.get("token")
    if not token:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        #JWT 라이브러리를 가져오고 토큰 인코딩 및 디코딩을 위한 비밀 키를 설정합니다.
        # 세션에 토큰이 있는지 확인하고 있으면 비밀 키를 사용하여 토큰을 디코딩하고 페이로드에서 사용자 ID를 검색합니다. 
        payload = jwt.decode(token, app.secret_key)
        userId = payload["userId"]
        return render_template("protected.html", userId=userId)
    
# 토큰이 만료되었거나 유효하지 않은 경우 대신 오류 응답을 반환합니다.
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    
    #글로벌 변수 ID와 PW는 요청 양식에서 사용자 이름과 암호를 대신 받기 때문에 더 이상 사용되지 않습니다.
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)
