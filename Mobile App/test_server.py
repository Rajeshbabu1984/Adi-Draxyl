from flask import Flask

app = Flask(__name__)

@app.route('/')
def test():
    return 'OK'

if __name__ == '__main__':
    print("Starting test Flask server...")
    app.run(host='0.0.0.0', port=5002, debug=False, use_reloader=False)
