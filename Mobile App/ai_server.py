from flask import Flask, request, jsonify
from flask_cors import CORS
from draxyl_ai import ai

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://gdllgvlk-8000.inc1.devtunnels.ms",
            "https://gdllgvlk-5001.inc1.devtunnels.ms"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

@app.route('/api/chat', methods=['POST'])
def chat():
    """Chat with Draxyl AI"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        
        if not message:
            return jsonify({
                'success': False,
                'error': 'No message provided'
            }), 400
        
        # Get AI response
        result = ai.chat(message)
        
        return jsonify({
            'success': True,
            'response': result['response'],
            'confidence': result['confidence'],
            'category': result['category']
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'service': 'Draxyl AI',
        'version': '1.0'
    }), 200

if __name__ == '__main__':
    print("=" * 60)
    print("🤖 DRAXYL AI SERVER")
    print("=" * 60)
    print("✅ AI Model loaded")
    print("✅ Flask server ready")
    print("🔗 Running on http://localhost:5003")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5003, debug=False)
