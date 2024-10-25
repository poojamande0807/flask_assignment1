from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, 
    jwt_required, get_jwt_identity, get_jwt
)
from datetime import timedelta
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
jwt = JWTManager(app)
users = {}
refresh_tokens = {}
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in refresh_tokens
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400
    if username in users:
        return jsonify({"msg": "User already exists"}), 400
    users[username] = {"password": password}
    return jsonify({"msg": "User registered successfully"}), 201
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username not in users or users[username]['password'] != password:
        return jsonify({"msg": "Bad username or password"}), 401
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    refresh_tokens[refresh_token] = username
    return jsonify(access_token=access_token, refresh_token=refresh_token), 200
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    return jsonify({"msg": "Accessed protected route"}), 200
@app.route('/token', methods=['POST'])
def refresh():
    data = request.json
    refresh_token = data.get('refreshToken')
    if refresh_token not in refresh_tokens:
        return jsonify({"msg": "Invalid refresh token"}), 401
    identity = refresh_tokens[refresh_token]
    new_access_token = create_access_token(identity=identity)
    return jsonify(access_token=new_access_token), 200
@app.route('/logout', methods=['POST'])
def logout():
    data = request.json
    refresh_token = data.get('refreshToken')
    if refresh_token in refresh_tokens:
        del refresh_tokens[refresh_token]
        return jsonify({"msg": "Successfully logged out"}), 200
    return jsonify({"msg": "Invalid refresh token"}), 400
if __name__ == '__main__':
    app.run(debug=True)