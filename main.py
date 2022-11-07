from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app=Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"]="jagfeyaufuf$asa#" #Cambiar por el que sea conveniente
jwt = JWTManager(app)

######## método lógin ################################
@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validate'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user,expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401

##################### Middleware
@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    print("endpoint", endPoint)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        print("ruta excluida",request.path)
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        print("user:", usuario)
        if usuario["rol"] is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
            print("validar permiso: ", tienePersmiso)
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401

def limpiarURL(url):
    partes = request.path.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url

def validarPermiso(endPoint,metodo,idRol):
    url=dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={
        "url":endPoint,
        "metodo":metodo
    }
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso

############### Redirecionamiento ######################################
############### Backend de seguridad ###################################
################ Usuarios #############################################
@app.route("/usuarios",methods=['GET'])
def getUsuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios",methods=['POST'])
def crearUsuario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['GET'])
def getUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['PUT'])
def modificarUsuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['DELETE'])
def eliminarUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################ Roles #############################################
@app.route("/roles",methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles",methods=['POST'])
def crearRol():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['GET'])
def getRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['PUT'])
def modificarRol(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['DELETE'])
def eliminarRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################ Permisos #############################################
@app.route("/permisos",methods=['GET'])
def getPermisos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos",methods=['POST'])
def crearPermiso():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['GET'])
def getPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['PUT'])
def modificarPermiso(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['DELETE'])
def eliminarPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

############### Backend de resultados ###################################
############### Candidato ################################################
@app.route("/candidato",methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/candidato'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidato",methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/candidato'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>",methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/candidato/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>",methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/candidato/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>",methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/candidato/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################# Partido ##########################
@app.route("/partido",methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/partido'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partido",methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/partido'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partido/<string:id>",methods=['GET'])
def getPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/partido/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partido/<string:id>",methods=['PUT'])
def modificarPartido(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/partido/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partido/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/partido/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################# Mesa ##########################
@app.route("/mesa",methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/mesa'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesa",methods=['POST'])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/mesa'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id>",methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/mesa/'+ id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id>",methods=['PUT'])
def modificarMesa(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/mesa/'+ id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id>",methods=['DELETE'])
def eliminarMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/mesa/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################# Resultado ##########################
@app.route("/resultado",methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/mesa/<string:id_mesa>/candidato/<string:id_candidato>",methods=['POST'])
def crearResultado(id_mesa,id_candidato):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] +"/resultado/" + '/mesa/' + id_mesa + "/candidato/" + id_candidato
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/<string:id>",methods=['GET'])
def getResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/'+ id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/<string:id_resultado>/mesa/<string:id_mesa>/candidato/<string:id_candidato>",methods=['PUT'])
def modificarResultado(id_resultado,id_mesa,id_candidato):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + "/resultado/" + id_resultado +'/mesa/' + id_mesa + "/candidato/" + id_candidato
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/<string:id_resultado>",methods=['DELETE'])
def eliminarResultado(id_resultado):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/' + id_resultado
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################## Visualazación de reportes #################
@app.route("/resultado/total_votos",methods=['GET'])
def getTotalVotosPorCandidato():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/' + '/total_votos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/candidato_mesa/mesa/<string:id_mesa>",methods=['GET'])
def getTotalVotosCandidatoPorMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/' + 'candidato_mesa/' + 'mesa/' + id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/votos_mesa",methods=['GET'])
def getTotalVotosPorMesa():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/' + 'votos_mesa'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/votos_partido",methods=['GET'])
def getTotalVotosPorPartido():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/' + 'votos_partido'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/partido_mesa/mesa/<string:id_mesa>",methods=['GET'])
def getTotalVotosPartidoPorMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/' + 'partido_mesa/' + 'mesa/' + id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/distribucion_porcentual",methods=['GET'])
def getDistribucionPorcentual():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-result"] + '/resultado/' + 'distribucion_porcentual'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])