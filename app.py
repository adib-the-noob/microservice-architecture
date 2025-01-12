from flask import Flask

server = Flask(__name__)

@server.route('/')
def hello_world():
    return 'Hello, World!'

if __name__ == '__main__':
    server.run(debug=True, port=8000)
