from flask import Flask,redirect,render_template,request,make_response,jsonify
from functools import wraps
import logging
from flask_httpauth import HTTPBasicAuth

logger = logging.getLogger('ESXI-HoneyPOT')
logger.setLevel(level=logging.INFO)
handler1 = logging.FileHandler('output.log')
handler2 = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler1.setFormatter(formatter)
handler2.setFormatter(formatter)
logger.addHandler(handler1)
logger.addHandler(handler2)


def create_app(test_config=None):
    app = Flask(__name__,instance_relative_config=True)
    auth = HTTPBasicAuth()
    users = [
        {'username':'nmsl','password':'1qaz@WSX'}
    ]

    @auth.verify_password
    def verify_password(username,password):
        useragent=request.headers.get('User-agent')
        ip = request.remote_addr
        for user in users:
            if user['username'] == username:
                return user['password']
        logger.info(request.base_url+" | 帳號:"+username+" 密碼:"+password + " IP:" + ip + " header:"+useragent)
        return None

    def response_head(headers={}):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                resp = make_response(f(*args, **kwargs))
                h = resp.headers
                for header, value in headers.items():
                    h[header] = value
                return resp
            return decorated_function
        return decorator

    def fake_header(f):
        return response_head({"Server": "Microsoft-IIS/7.5", 
            "X-Powered-By": "ASP.NET",
            "X-VMWARE-VCLOUD-REQUEST-ID":"e0605bb3-422d-4235-bcb1-1d987c45e7db",
            "X-VMWARE-VCLOUD-CEIP-ID":"d64325b8-dc30-4e10-a8d3-4b9d1bd92155",
            "X-Frame-Options":"SAMEORIGIN",
            "Content-Type":"text/html;charset=utf-8",
            "Strict-Transport-Security":"max-age=31536000 ; includeSubDomains",
            "X-XSS-Protection":"1; mode=block",
            "X-Content-Type-Options":"nosniff",
            "Content-Security-Policy":"default-src *  data: blob: 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; connect-src * 'unsafe-inline'; img-src * data: blob: 'unsafe-inline'; frame-src *; style-src * data: blob: 'unsafe-inline'; font-src * data: blob: 'unsafe-inline';",
            "Vary":"Accept-Encoding, User-Agent"})(f)

    @auth.error_handler
    @fake_header
    def unauthorized():
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401) 
        return render_template("401.html"),401
        
    @app.route('/esxi/')
    @app.route('/config/')
    @app.route('/aspnet_client/')
    @app.route('/backup/')
    @app.route('/admin/')
    @app.route('/upload/')
    @fake_header
    @auth.login_required
    def fake_auth():
        return redirect('/')

    @app.route('/esxi/login.aspx',methods=['GET'])
    @fake_header
    def owa():
        return render_template("login.html")

    @app.route('/')
    @fake_header
    def index():
        return redirect('/esxi/login.aspx')

    @app.route('/esxi/auth.aspx',methods=['GET','POST'])
    @fake_header
    def auth():
        useragent=request.headers.get('User-agent')
        ip = request.remote_addr
        print (useragent)
        print (ip)
        if request.method == 'GET':
            return redirect('/esxi/login.aspx?redirect=1',302)
        else:
            username = ""
            password = ""
            if "username" in request.form:
                username = request.form["username"]
            if "password" in request.form:
                password = request.form["password"]
            print(username)
            logger.info(request.base_url+" | 帳號:"+username+" 密碼:"+password + " IP:" + ip + " header:"+useragent)
            return redirect('/esxi/login.aspx?redirect=1',302)
    
    @app.errorhandler(404)
    @fake_header
    def page_404(error):
        return render_template("404.html"),404 

    @app.errorhandler(401)
    @fake_header
    def page_401(error):
        return render_template("401.html"),401
   
    @app.errorhandler(405)
    @fake_header
    def page_405(error):
        return render_template("401.html"),405

    return app
if __name__ == '__main__':
    create_app().run(debug=True,port=8080,host="0.0.0.0")