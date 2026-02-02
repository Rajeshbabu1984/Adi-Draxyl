import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import traceback

app = Flask(__name__)

# CORS for devtunnel and localhost
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

# Replace with your Gemini API key
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'Draxyl_API_key')
GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=' + GEMINI_API_KEY

@app.route('/api/chat', methods=['POST'])
def chat():
    print('Received /api/chat request')
    data = request.get_json()
    user_message = data.get('message', '')
    if not user_message:
        return jsonify({'success': False, 'response': 'No message provided.'}), 400

    # Gemini expects a specific JSON format
    payload = {
        "contents": [
            {"parts": [{"text": user_message}]}
        ]
    }
    try:
        r = requests.post(GEMINI_API_URL, json=payload)
        r.raise_for_status()
        gemini_data = r.json()
        # Debug: print Gemini API response
        print('Gemini API raw response:', gemini_data)
        # Extract the response text
        response_text = gemini_data['candidates'][0]['content']['parts'][0]['text']
        return jsonify({'success': True, 'response': response_text, 'confidence': 100})
    except Exception as e:
        print('Gemini API error:', str(e))
        traceback.print_exc()
        # Try to show Gemini error message if present
        try:
            error_json = r.json()
            error_message = error_json.get('error', {}).get('message', str(e))
        except Exception:
            error_message = str(e)
        return jsonify({'success': False, 'response': f'Gemini API Error: {error_message}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True, use_reloader=False)
