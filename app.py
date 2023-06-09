from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
app = Flask(__name__)

from bson.json_util import dumps
from bson.objectid import ObjectId

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

@app.route('/main')
def main():
    return render_template('main.html')

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

    # if not id_receive or not pw_receive or not nickname_receive or not retype_pw_receive :
    #     # 필수 입력 항목이 비어 있는지 확인하고, 하나라도 비어 있다면 오류 메시지를 반환함
    #     return jsonify({'result': '입력되지 않은 값이 있습니다.'})
    
    # if pw_receive != retype_pw_receive:
    #     # 입력받은 비밀번호가 일치하는지 하고 일치하지 않으면 오류 메세지를 반환함
    #     # 프론트에서 처리하게 하였으므로 불필요 그러나 사용자가 이것저것 눌러보다가 오동작할 경우를 대비하여 구현.
    #     # 현 시점에서는 불필요하다고 판단되어 주석처리
    #     return jsonify({'result': '비밀번호가 일치하지 않습니다.'})
    
    # 입력받은 사용자 ID가 이미 사용 중인지 확인
    if db.user.find_one({'$or': [{'id': id_receive}, {'nick': nickname_receive}]}):
        return jsonify({'result': '이미 사용 중인 아이디 또는 닉네임입니다.'})

    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest() # 비밀번호를 해싱하여 보안 강화

    # 사용자 ID가 사용 가능하면, 사용자 정보를 데이터베이스에 저장함
    db.user.insert_one({'id': id_receive, 'pw': pw_hash, 'nick': nickname_receive})

    return jsonify({'result': 'success'}) #성공 메세지 반환

# 로그인
@app.route('/api/login', methods=['POST'])
def api_login():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']

    # 회원가입 때와 같은 방법으로 pw를 암호화합니다.
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    # id, 암호화된pw을 가지고 해당 유저를 찾습니다.
    result = db.user.find_one({'id': id_receive, 'pw': pw_hash})

    # 찾으면 JWT 토큰을 만들어 발급합니다.
    if result is not None:
        # JWT 토큰 생성
        payload = {
            'id': id_receive,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=10000)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        # token을 줍니다.
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})
    
    # 로그아웃
@app.route('/api/logout', methods=['POST'])
def api_logout():
    token_receive = request.headers.get('Authorization')
    
    try:
        # 토큰에서 유저정보 디코딩
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['id']
        
        # 디코딩이 성공하면 토큰을 블랙리스트에 추가합니다.
        db.blacklist.insert_one({'token': token_receive})
        
        return jsonify({'result': 'success', 'msg': '로그아웃 되었습니다.'})
    
    except jwt.exceptions.DecodeError:
        # 토큰 디코딩 실패 시
        return jsonify({'result': 'fail', 'msg': '올바른 토큰이 아닙니다.'})


# 보안: 로그인한 사용자만 통과할 수 있는 API
@app.route('/api/isAuth', methods=['GET'])
def api_valid():
    token_receive = request.cookies.get('mytoken')
    try:
        # token을 시크릿키로 디코딩합니다.
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
        userinfo = db.user.find_one({'id': payload['id']}, {'_id': 0})
        return jsonify({'result': 'success', 'nickname': userinfo['nick']})
    except jwt.ExpiredSignatureError:
        # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
        return jsonify({'result': 'fail', 'msg': '로그인 시간이 만료되었습니다.'})
    except jwt.exceptions.DecodeError:
        # 로그인 정보가 없으면 에러가 납니다!
        return jsonify({'result': 'fail', 'msg': '로그인 정보가 존재하지 않습니다.'})
    
#사용자 정보 받아오기


# Posting으로 받아오기
@app.route("/booksbooks", methods=["POST"])
def book_post():
    nickname_receive = request.form['nickname_give']
    url_receive = request.form['url_give']
    review_receive = request.form['review_give']
    star_receive = request.form['star_give']

    headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'}
    data = requests.get(url_receive,headers=headers)

    soup = BeautifulSoup(data.text, 'html.parser')

    title_receive = soup.select_one('.gd_name').text
    desc_receive = soup.select_one('.infoWrap_txt').text
    #이미지부분 클래스로 받아오기
    image_receive = soup.select_one('.gImg')['src']

    doc = {
        'nickname':nickname_receive,
        'title':title_receive,
        'desc':desc_receive,
        'image':image_receive,
        'review':review_receive,
        'star':star_receive
    }
    db.booksbooks.insert_one(doc)

    return jsonify({'msg':'저장완료!'})

#Listing으로 올리기
@app.route("/booksbooks", methods=["GET"])
def book_get():
    all_book = list(db.booksbooks.find())
    return jsonify({'result': dumps(all_book)})

#card-수정하기
@app.route("/booksbooks/edit", methods = ["POST"])
def edit():
    receive_id = request.form['edit_id']
    receive_star = request.form['star_edit']
    receive_review = request.form['review_edit']
    db.booksbooks.update_one({"_id" : ObjectId(receive_id)} , {"$set" : {"star" : receive_star, "review" : receive_review}})
    return jsonify({'msg' : '수정완료!'})

#card-삭제하기
@app.route("/booksbooks/delete", methods=["POST"])
def delete():
    receive_id = request.form['delete_id']
    db.booksbooks.delete_one({'_id' : ObjectId(receive_id)})
    return jsonify({'msg' : '삭제완료!'})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)