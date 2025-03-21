from flask import Flask, request, jsonify, render_template, redirect, make_response, url_for, request, Response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, verify_jwt_in_request
import datetime, json, re
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'null' #! notevolemente sensibile
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  #todo - Metti True in produzione per HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    musegamepoint = db.Column(db.Integer, nullable=True)
    musegamedone = db.Column(db.String(50), nullable=False)
    musegamefound = db.Column(db.String(50), nullable=False)

class MuseGameQuiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)
    options = db.Column(db.JSON, nullable=False)
    correct_option_id = db.Column(db.Integer, nullable=False)

class MuseGameSet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    setids = db.Column(db.String(50), nullable=False)
    poi = db.Column(db.JSON, nullable=False)

with app.app_context():
    db.create_all()

# Funzioni di servizio
def read_settings():
    try:
        with open('static/settings.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {
    "winPoints": 10,
    "losePoints": -10,
    "mapImage": "https://lh3.googleusercontent.com/pw/AP1GczMbq1L8JLFLGD9RZrFssUNabWlWyRottVlsMVAtpXKHkkv99fyHbaRtjPC1uVrkY09OsxOeZmsoIaeReNQ9B7TWXKFfKqKwWFWzIbvN5-lx9Mu50amVG8-lCH3egNYfVUK8bit1RzSQ-8GVKUws7NEufg=w1238-h1438-s-no-gm"
}

def write_settings(data):
    with open('static/settings.json', 'w') as f:
        json.dump(data, f, indent=4)

def verify_jwt_and_check_user():
    verify_jwt_in_request()
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user:
        resp = make_response(redirect(url_for('page_login')))
        resp.set_cookie("access_token_cookie", '', expires=0)
        return resp
    return user

def getUserPublicData(username):
    user = User.query.filter_by(username=username).first()
    return {"id":user.id,"name":user.username,"role":user.role,"score":user.musegamepoint}

def jwt_required_and_user_exists(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        username = get_jwt_identity()
        user = User.query.filter_by(username=username).first()
        if not user:
            resp = make_response(redirect(url_for('page_login')))
            resp.set_cookie("access_token_cookie", '', expires=0)
            return resp
        return fn(*args, **kwargs)
    return wrapper


# Fallback Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e), 404

@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    return make_response(redirect(url_for('page_login')))

# Basic
@app.route('/')
def page_home():
    return redirect("https://internationalsteamchannel.my.canva.site")

@app.route('/qr/<int:quizid>')
def page_qr(quizid):
    try:
        verify_jwt_and_check_user()
        user = User.query.filter_by(username=get_jwt_identity()).first() # Se l'utente è valido, prosegui con il resto della logica
        userfound = json.loads(user.musegamefound)
        if quizid not in userfound: userfound.append(quizid)
        user.musegamefound = str(userfound)
        db.session.commit()
        return redirect(f"/quiz/{quizid}")
    except:
        return make_response(redirect(url_for("page_login")))


@app.route('/map')
def page_map():
    try:
        user_or_response = verify_jwt_and_check_user() # Verifica JWT e utente
        if isinstance(user_or_response, Response): # Se la funzione ha restituito una risposta (quindi un errore è stato rilevato)
            return user_or_response  # Esce dalla funzione e restituisce la risposta di errore
        return render_template('map.html', user=getUserPublicData(get_jwt_identity()), settings=read_settings())
    except:
        return render_template('map.html', settings=read_settings())

@app.route('/quiz/<int:id>')
@jwt_required_and_user_exists
def page_quiz(id):
    user = User.query.filter_by(username=get_jwt_identity()).first()
    set = MuseGameSet.query.filter_by(id=str(id)).first()
    if id not in json.loads(user.musegamefound):
        return render_template("quizError.html", user=getUserPublicData(get_jwt_identity()), settings=read_settings())
    return render_template('quiz.html', user=getUserPublicData(get_jwt_identity()), settings=read_settings(), quizlist=set.setids)


@app.route('/scoreboard')
def page_scoreboard():
    try:
        user_or_response = verify_jwt_and_check_user() # Verifica JWT e utente
        if isinstance(user_or_response, Response): # Se la funzione ha restituito una risposta (quindi un errore è stato rilevato)
            return user_or_response  # Esce dalla funzione e restituisce la risposta di errore
        return render_template('scoreboard.html', user=getUserPublicData(get_jwt_identity()), settings=read_settings())
    except:
        return render_template('scoreboard.html', settings=read_settings())

# Account Managing Page
@app.route('/login')
def page_login():
    return render_template('login.html')
@app.route('/register')
def page_register():
    return render_template('register.html')
@app.route('/account')
@jwt_required_and_user_exists
def page_account():
    return render_template('account.html', user=getUserPublicData(get_jwt_identity()))
@app.route('/admin')
@jwt_required_and_user_exists
def page_admin():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    if user.role != "admin":
        return render_template('404.html'),404
    return render_template('admin.html')

# Account Managing Api
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username già esistente","errcode":4003}), 400

    new_user = User(username=data['username'], password=data['password'], role="user", musegamedone="[]", musegamefound="[1,2,3,4,5,6,7]", musegamepoint=0)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.username, expires_delta=datetime.timedelta(days=7))
    resp = make_response(jsonify({"message": "Registrazione e login effettuati"}))
    resp.set_cookie('access_token_cookie', access_token, httponly=True, samesite='Lax')
    return resp

@app.route('/api/login', methods=['POST'])
def api_login(request=request):
    data = request.json
    user = User.query.filter_by(username=data['username'], password=data['password']).first()

    if user:
        access_token = create_access_token(identity=user.username, expires_delta=datetime.timedelta(days=7))
        resp = make_response(jsonify({"message": "Login effettuato"}))
        resp.set_cookie('access_token_cookie', access_token, httponly=True, samesite='Lax')
        return resp
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Credenziali errate","errcode":4002}), 401
    else:
        return jsonify({"message": "Profilo inesistente","errcode":4001}), 401

@app.route('/api/logout')
@jwt_required_and_user_exists
def api_logout():
    resp = make_response(redirect(url_for('page_login')))
    resp.set_cookie("access_token_cookie", '', expires=0)
    return resp

@app.route('/api/unregister')
@jwt_required_and_user_exists
def api_unregister():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    db.session.delete(user)
    db.session.commit()
    resp = make_response(redirect(url_for('page_register')))
    resp.set_cookie("access_token_cookie", '', expires=0)
    return resp

@app.route('/api/update-me', methods=["POST"])
@jwt_required_and_user_exists
def api_update_me():
    data  = request.json
    user = User.query.filter_by(username=get_jwt_identity()).first()
    user.username = data["username"]
    print(data["password"])
    if data["password"] != "":
        user.password = data["password"]
    db.session.commit()
    resp = make_response(jsonify({"message": "Dati aggiornati"}))
    resp.set_cookie('access_token_cookie', create_access_token(identity=data["username"], expires_delta=datetime.timedelta(days=7)), httponly=True, samesite='Lax')
    return resp

# Admin Apis
@app.route("/admin/api/sets")
@jwt_required_and_user_exists
def get_sets():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404

    sets = MuseGameSet.query.all()
    set_list = [{
        "id": q.id,
        "setids": q.setids,
        "poi": q.poi
    } for q in sets]

    return jsonify(set_list)

@app.route("/admin/api/edit-set", methods=["POST"])
@jwt_required_and_user_exists
def edit_set():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404
    
    data = request.json
    set_id = data.get("id")

    set = MuseGameSet.query.filter_by(id=set_id).first()
    if not set:
        return jsonify({"error": "Quiz non trovato"}), 404
    if "setids" in data:
        if re.match(r"^\[\s*(\d+\s*(,\s*\d+\s*)*)?\]$", data["setids"]):
            set.setids = str(data["setids"])
        else:
            return jsonify({"error": "Formato non valido per i i setIDs"}), 400
    if "poi" in data:
        set.poi = data["poi"]

    db.session.commit()
    return jsonify({"message": f"Quiz {set_id} aggiornato con successo!"})

@app.route("/admin/api/add-set", methods=["POST"])
@jwt_required_and_user_exists
def add_set():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404

    data = request.json

    if "setids" not in data or "poi" not in data:
        return jsonify({"error": "Dati mancanti"}), 400

    new_set = MuseGameSet(
        setids=data["setids"],
        poi=data["poi"]
    )

    db.session.add(new_set)
    db.session.commit()
    return jsonify({"message": f"Nuovo quiz aggiunto con successo!", "id": new_set.id})

@app.route("/admin/api/delete-set", methods=["GET"])
@jwt_required_and_user_exists
def delete_set():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404

    set_id = request.args.get("id")

    set = MuseGameSet.query.filter_by(id=set_id).first()
    if not set:
        return jsonify({"error": "Quiz non trovato"}), 404

    db.session.delete(set)
    db.session.commit()
    return jsonify({"message": f"Quiz {set_id} eliminato con successo!"})


@app.route("/admin/api/quizzes")
@jwt_required_and_user_exists
def get_quizzes():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404

    quizzes = MuseGameQuiz.query.all()
    quiz_list = [{
        "id": q.id,
        "title": q.title,
        "options": q.options,
        "correct_option_id": q.correct_option_id
    } for q in quizzes]

    return jsonify(quiz_list)

@app.route("/admin/api/edit-quiz", methods=["POST"])
@jwt_required_and_user_exists
def edit_quiz():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404

    data = request.json
    quiz_id = data.get("id")

    quiz = MuseGameQuiz.query.filter_by(id=quiz_id).first()
    if not quiz:
        return jsonify({"error": "Quiz non trovato"}), 404

    if "title" in data:
        quiz.title = data["title"]
    if "options" in data:
        quiz.options = data["options"]
    if "correct_option_id" in data:
        quiz.correct_option_id = int(data["correct_option_id"])

    db.session.commit()
    return jsonify({"message": f"Quiz {quiz_id} aggiornato con successo!"})

@app.route("/admin/api/add-quiz", methods=["POST"])
@jwt_required_and_user_exists
def add_quiz():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404

    data = request.json

    if "title" not in data or "options" not in data or "correct_option_id" not in data or "poi" not in data:
        return jsonify({"error": "Dati mancanti"}), 400

    if len(data["options"]) < 2:
        return jsonify({"error": "Devi inserire almeno 2 opzioni"}), 400

    new_quiz = MuseGameQuiz(
        title=data["title"],
        options=data["options"],
        correct_option_id=int(data["correct_option_id"])
    )

    db.session.add(new_quiz)
    db.session.commit()
    return jsonify({"message": f"Nuovo quiz aggiunto con successo!", "id": new_quiz.id})

@app.route("/admin/api/delete-quiz", methods=["GET"])
@jwt_required_and_user_exists
def delete_quiz():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404

    quiz_id = request.args.get("id")

    quiz = MuseGameQuiz.query.filter_by(id=quiz_id).first()
    if not quiz:
        return jsonify({"error": "Quiz non trovato"}), 404

    db.session.delete(quiz)
    db.session.commit()
    return jsonify({"message": f"Quiz {quiz_id} eliminato con successo!"})


@app.route("/admin/api/edit-user", methods=["POST"])
@jwt_required_and_user_exists
def edit_user():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'), 404
    data = request.json
    username = data.get("target")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Utente non trovato"}), 404

    if "new-username" in data and data["new-username"] != username:
        existing_user = User.query.filter_by(username=data["new-username"]).first()
        if existing_user:
            return jsonify({"error": "Il nuovo username è già in uso"}), 400
        user.username = data["new-username"]

    if "new-password" in data:
        user.password = data["new-password"]
    if "new-role" in data:
        user.role = data["new-role"]
    if "new-musegamepoint" in data:
        user.musegamepoint = int(data["new-musegamepoint"])

    if "new-musegamedone" in data:
        if re.match(r"^\[\s*(\d+\s*(,\s*\d+\s*)*)?\]$", data["new-musegamedone"]):
            user.musegamedone = str(data["new-musegamedone"])
        else:
            return jsonify({"error": "Formato non valido per i quiz completati"}), 400

    if "new-musegamefound" in data:
        if re.match(r"^\[\s*(\d+\s*(,\s*\d+\s*)*)?\]$", data["new-musegamefound"]):
            user.musegamefound = str(data["new-musegamefound"])
        else:
            return jsonify({"error": "Formato non valido per i quiz trovati"}), 400

    db.session.commit()
    return jsonify({"message": f"Utente aggiornato con successo!"})

@app.route("/admin/api/delete-user", methods=["GET"])
@jwt_required_and_user_exists
def delete_user():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'),404
    username = request.args.get("target")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Utente non trovato"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": f"Utente {username} eliminato con successo!"})

@app.route("/admin/api/users", methods=["GET"])
@jwt_required_and_user_exists
def get_users():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'),404
    users = User.query.all()
    users_list = [{
        "id": u.id,
        "username": u.username,
        "password": u.password,
        "role": u.role,
        "musegamepoint": u.musegamepoint,
        "musegamedone": u.musegamedone,
        "musegamefound": u.musegamefound
    } for u in users]

    return jsonify(users_list)

@app.route('/admin/api/settings', methods=['GET'])
@jwt_required_and_user_exists
def get_settings():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'),404
    return jsonify(read_settings())

@app.route('/admin/api/save-settings', methods=['POST'])
@jwt_required_and_user_exists
def save_settings():
    agent = User.query.filter_by(username=get_jwt_identity()).first()
    if agent.role != "admin":
        return render_template('404.html'),404
    write_settings(request.get_json())
    return jsonify({"message": "Impostazioni salvate con successo!"})

# MuseGame Apis
@app.route('/api/scoreboard')
def api_scoreboard():
    users = User.query.order_by(User.musegamepoint.desc()).all()
    leaderboard = [{"username": user.username, "musegamepoint": user.musegamepoint or 0} for user in users if isinstance(user.musegamepoint,int)]
    return jsonify(leaderboard)

@app.route("/api/quiz")
def api_quiz():
    quiz = MuseGameQuiz.query.filter_by(id=request.args.get("id")).first()
    return jsonify({"title":quiz.title,"options":quiz.options})

@app.route("/api/quiz-try")
@jwt_required_and_user_exists
def api_quiz_try():
    quiz = MuseGameQuiz.query.filter_by(id=request.args.get("quizid")).first()
    user = User.query.filter_by(username=get_jwt_identity()).first()
    userdone = json.loads(user.musegamedone)
    if int(request.args.get("quizid")) in userdone:
        return jsonify({"status":"error","correct":quiz.correct_option_id})
    if quiz.correct_option_id == int(request.args.get("option")):
        userdone.append(int(request.args.get("quizid")))
        user.musegamedone = str(userdone)
        user.musegamepoint += read_settings()["winPoints"]
        db.session.commit()
        return jsonify({"status":"win"})
    user.musegamepoint += read_settings()["losePoints"]
    db.session.commit()
    return jsonify({"status":"lose"})

@app.route("/api/quiz-poi")
def api_quiz_poi():
    if request.args.get("id") == "all":
        data = MuseGameSet.query.all()
        return jsonify([quiz.poi for quiz in data if data])
    quiz = MuseGameSet.query.filter_by(id=request.args.get("id")).first()
    if not quiz:
        return jsonify({"error": "Quiz non trovato"}), 404
    return jsonify(quiz.poi)


if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True,port=5000)