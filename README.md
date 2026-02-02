# Draxyl Platform

A comprehensive web application platform featuring messaging, AI integration, and user management.

## Features

- **User Authentication**: Secure signup/login with bcrypt password hashing
- **Real-time Messaging**: Socket.IO-based messaging system
- **AI Integration**: Built-in AI server for intelligent responses
- **Admin Dashboard**: User management and system administration
- **Security**: JWT authentication, CORS protection, rate limiting

## Servers

The platform consists of multiple servers:
- **Main App** (Port 5000): User authentication and core functionality
- **Messaging Server** (Port 5001): Real-time chat and messaging
- **AI Server** (Port 5003): AI-powered features
- **HTTP Server** (Port 8000): Static file serving

## Installation

1. Clone the repository
2. Install Python dependencies:
```bash
pip install flask flask-cors flask-limiter flask-socketio bcrypt pyjwt cryptography
```

## Running the Application

Start all servers:
```bash
cd "Mobile App"
python app.py          # Port 5000
python messaging_server.py  # Port 5001
python ai_server.py    # Port 5003
```

## Technologies Used

- Python/Flask
- Socket.IO
- SQLite
- HTML/CSS/JavaScript
- Bcrypt encryption
- JWT authentication

## License

Private project - All rights reserved

## Author

Rajeshbabu Jayaraman
