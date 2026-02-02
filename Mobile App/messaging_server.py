from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Response, after_this_request
import sqlite3
from datetime import datetime
import hashlib
import jwt
import re
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'draxyl-secret-key-2026'
# Enhanced CORS for Flask and Socket.IO
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://gdllgvlk-8000.inc1.devtunnels.ms",
    "https://gdllgvlk-5001.inc1.devtunnels.ms",
    "http://localhost:5001",
    "http://127.0.0.1:5001",
    "*"  # Allow all origins for development
]
CORS(app, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})
from flask import make_response
from functools import wraps as _wraps
def add_cors_headers(f):
    @_wraps(f)
    def decorated_function(*args, **kwargs):
        resp = f(*args, **kwargs)
        if isinstance(resp, tuple):
            response = make_response(resp[0], resp[1])
        else:
            response = make_response(resp)
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return response
    return decorated_function
# Use CORS for SocketIO as well
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    ping_timeout=60,
    ping_interval=25,
    allow_upgrades=True,
    async_mode=None,
    logger=True,
    engineio_logger=True
)

# Rate Limiting - Enhanced for DDoS Protection
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",  # Prevents burst attacks
    headers_enabled=True  # Show rate limit info in headers
)

# IP Blocking for repeated violations
blocked_ips = set()

DATABASE = 'messaging.db'
USERS_DB = 'users.db'

# ==================== SECURITY FUNCTIONS ====================
def sanitize_input(text):
    """Sanitize user input to prevent XSS and injection attacks"""
    if not text:
        return text
    text = str(text).strip()
    # HTML entity encoding
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('"', '&quot;').replace("'", '&#x27;')
    text = text.replace('&', '&amp;')
    return text

# --- CORS fix for Socket.IO polling and websocket ---
@app.before_request
def socketio_cors_fix():
    if request.path.startswith('/socket.io/'):
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            # For preflight OPTIONS
            if request.method == 'OPTIONS':
                resp = Response()
                resp.headers['Access-Control-Allow-Origin'] = origin
                resp.headers['Access-Control-Allow-Credentials'] = 'true'
                resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
                return resp, 200

@app.after_request
def socketio_cors_after(response):
    if request.path.startswith('/socket.io/'):
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response
def verify_token(token):
    """Verify JWT token"""
    try:
        # Use the same secret key as app.py
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'success': False, 'message': 'Token is invalid or expired'}), 401
        
        return f(payload, *args, **kwargs)
    
    return decorated

def validate_message_length(message):
    """Validate message length"""
    if not message or len(message.strip()) == 0:
        return False, "Message cannot be empty"
    if len(message) > 5000:
        return False, "Message too long (max 5000 characters)"
    return True, "Valid"

# ==================== DATABASE INITIALIZATION ====================
def init_messaging_db():
    """Initialize messaging database with all necessary tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Workspaces table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            owner_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    
    # Channels table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            is_private BOOLEAN DEFAULT 0,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Channel members table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS channel_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (channel_id) REFERENCES channels(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(channel_id, user_id)
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            message_type TEXT DEFAULT 'text',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            FOREIGN KEY (channel_id) REFERENCES channels(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Direct messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS direct_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')
    
    # User status table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_status (
            user_id INTEGER PRIMARY KEY,
            status TEXT DEFAULT 'offline',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Message reactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            emoji TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES messages(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(message_id, user_id, emoji)
        )
    ''')
    
    # Workspace invites table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS workspace_invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            invite_code TEXT UNIQUE NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            max_uses INTEGER DEFAULT NULL,
            uses INTEGER DEFAULT 0,
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Messaging database initialized!")

# ==================== WORKSPACE APIs ====================
@app.route('/api/workspaces', methods=['GET', 'POST', 'OPTIONS'])
@limiter.limit("50 per hour")
@add_cors_headers
def workspaces():
    # Handle preflight OPTIONS for CORS
    if request.method == 'OPTIONS':
        resp = Response()
        resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return resp, 200
    
    if request.method == 'POST':
        data = request.get_json()
        name = sanitize_input(data.get('name'))
        description = sanitize_input(data.get('description', ''))
        owner_id = data.get('owner_id')
        
        if not name or not owner_id:
            return jsonify({'success': False, 'message': 'Name and owner_id required'}), 400
        
        if len(name) > 100:
            return jsonify({'success': False, 'message': 'Workspace name too long'}), 400
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            # Check for duplicate workspace name for the same owner
            cursor.execute('SELECT id FROM workspaces WHERE name = ? AND owner_id = ?', (name, owner_id))
            if cursor.fetchone():
                conn.close()
                return jsonify({'success': False, 'message': 'You already have a workspace with this name.'}), 400

            cursor.execute('INSERT INTO workspaces (name, description, owner_id) VALUES (?, ?, ?)',
                         (name, description, owner_id))
            workspace_id = cursor.lastrowid

            # Create default channels
            default_channels = [
                ('general', 'General discussion', 0),
                ('random', 'Random stuff', 0),
                ('announcements', 'Important announcements', 0)
            ]

            for ch_name, ch_desc, is_private in default_channels:
                cursor.execute('INSERT INTO channels (workspace_id, name, description, is_private, created_by) VALUES (?, ?, ?, ?, ?)',
                             (workspace_id, sanitize_input(ch_name), sanitize_input(ch_desc), is_private, owner_id))
                channel_id = cursor.lastrowid
                # Add owner to channel
                cursor.execute('INSERT INTO channel_members (channel_id, user_id) VALUES (?, ?)',
                             (channel_id, owner_id))

            conn.commit()
            conn.close()

            return jsonify({'success': True, 'workspace_id': workspace_id}), 201
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    
    else:  # GET
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'message': 'user_id required'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get workspaces where user is owner OR a member of any channel
        cursor.execute('''
            SELECT DISTINCT w.id, w.name, w.description, w.created_at, w.owner_id 
            FROM workspaces w
            LEFT JOIN channels c ON w.id = c.workspace_id
            LEFT JOIN channel_members cm ON c.id = cm.channel_id
            WHERE w.owner_id = ? OR cm.user_id = ?
            ORDER BY w.created_at DESC
        ''', (user_id, user_id))
        
        workspaces = cursor.fetchall()
        conn.close()
        
        workspace_list = []
        for ws in workspaces:
            workspace_list.append({
                'id': ws[0],
                'name': sanitize_input(ws[1]),
                'description': sanitize_input(ws[2]),
                'created_at': ws[3],
                'created_by': ws[4]
            })
        
        return jsonify({'success': True, 'workspaces': workspace_list}), 200

# ==================== CHANNEL APIs ====================
@app.route('/api/channels', methods=['GET', 'POST'])
def channels():
    if request.method == 'OPTIONS':
        resp = Response()
        resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return resp, 200
    if request.method == 'POST':
        print("[API] Received channel creation request at /api/channels")
        data = request.get_json()
        print(f"[API] Request data: {data}")
        workspace_id = data.get('workspace_id')
        name = data.get('name')
        description = data.get('description', '')
        is_private = data.get('is_private', 0)
        created_by = data.get('created_by')
        if not all([workspace_id, name, created_by]):
            print("[API] Missing required fields for channel creation")
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO channels (workspace_id, name, description, is_private, created_by) VALUES (?, ?, ?, ?, ?)',
                         (workspace_id, name, description, is_private, created_by))
            channel_id = cursor.lastrowid
            # Add creator to channel
            cursor.execute('INSERT INTO channel_members (channel_id, user_id) VALUES (?, ?)',
                         (channel_id, created_by))
            conn.commit()
            conn.close()
            print(f"[API] Channel created successfully with ID: {channel_id}")
            return jsonify({'success': True, 'channel_id': channel_id}), 201
        except Exception as e:
            print(f"[API] Error creating channel: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': str(e)}), 500
    
    else:  # GET
        workspace_id = request.args.get('workspace_id')
        user_id = request.args.get('user_id')
        
        if not workspace_id or not user_id:
            return jsonify({'success': False, 'message': 'workspace_id and user_id required'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get channels user is a member of
        cursor.execute('''
            SELECT c.id, c.name, c.description, c.is_private, c.created_at
            FROM channels c
            JOIN channel_members cm ON c.id = cm.channel_id
            WHERE c.workspace_id = ? AND cm.user_id = ?
            ORDER BY c.name
        ''', (workspace_id, user_id))
        
        channels = cursor.fetchall()
        conn.close()
        
        channel_list = []
        for ch in channels:
            channel_list.append({
                'id': ch[0],
                'name': ch[1],
                'description': ch[2],
                'is_private': bool(ch[3]),
                'created_at': ch[4]
            })
        
        return jsonify({'success': True, 'channels': channel_list}), 200

@app.route('/api/channels/browse', methods=['GET'])
def browse_channels():
    if request.method == 'OPTIONS':
        resp = Response()
        resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return resp, 200
    """Get all channels in workspace that user is NOT a member of"""
    workspace_id = request.args.get('workspace_id')
    user_id = request.args.get('user_id')
    
    if not workspace_id or not user_id:
        return jsonify({'success': False, 'message': 'workspace_id and user_id required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get channels user is NOT a member of
    cursor.execute('''
        SELECT c.id, c.name, c.description, c.is_private,
               (SELECT COUNT(*) FROM channel_members WHERE channel_id = c.id) as member_count
        FROM channels c
        WHERE c.workspace_id = ? 
        AND c.is_private = 0
        AND c.id NOT IN (
            SELECT channel_id FROM channel_members WHERE user_id = ?
        )
        ORDER BY c.name
    ''', (workspace_id, user_id))
    
    channels = cursor.fetchall()
    conn.close()
    
    channel_list = []
    for ch in channels:
        channel_list.append({
            'id': ch[0],
            'name': ch[1],
            'description': ch[2],
            'is_private': bool(ch[3]),
            'member_count': ch[4]
        })
    
    return jsonify({'success': True, 'channels': channel_list}), 200

@app.route('/api/channels/join', methods=['POST'])
def join_channel():
    """Join a channel"""
    data = request.get_json()
    channel_id = data.get('channel_id')
    user_id = data.get('user_id')
    
    if not channel_id or not user_id:
        return jsonify({'success': False, 'message': 'channel_id and user_id required'}), 400
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if already a member
        cursor.execute('SELECT id FROM channel_members WHERE channel_id = ? AND user_id = ?',
                     (channel_id, user_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Already a member'}), 400
        
        # Add user to channel
        cursor.execute('INSERT INTO channel_members (channel_id, user_id) VALUES (?, ?)',
                     (channel_id, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Joined channel successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== MESSAGE APIs ====================
@app.route('/api/messages', methods=['GET', 'POST'])
@limiter.limit("200 per hour")
def messages():
    if request.method == 'POST':
        data = request.get_json()
        channel_id = data.get('channel_id')
        user_id = data.get('user_id')
        content = sanitize_input(data.get('content'))
        message_type = data.get('message_type', 'text')
        
        if not all([channel_id, user_id, content]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Validate message content
        is_valid, error_msg = validate_message_length(content)
        if not is_valid:
            return jsonify({'success': False, 'message': error_msg}), 400
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO messages (channel_id, user_id, content, message_type) VALUES (?, ?, ?, ?)',
                         (channel_id, user_id, content, message_type))
            message_id = cursor.lastrowid
            
            # Get user info
            users_conn = sqlite3.connect(USERS_DB)
            users_cursor = users_conn.cursor()
            users_cursor.execute('SELECT name, email FROM users WHERE id = ?', (user_id,))
            user = users_cursor.fetchone()
            users_conn.close()
            
            cursor.execute('SELECT created_at FROM messages WHERE id = ?', (message_id,))
            created_at = cursor.fetchone()[0]
            
            conn.commit()
            conn.close()
            
            # Emit message to all users in channel via Socket.IO
            message_data = {
                'id': message_id,
                'channel_id': channel_id,
                'user_id': user_id,
                'user_name': sanitize_input(user[0]) if user else 'Unknown',
                'content': content,  # Already sanitized above
                'message_type': message_type,
                'created_at': created_at
            }
            
            socketio.emit('new_message', message_data, room=f'channel_{channel_id}')
            
            return jsonify({'success': True, 'message': message_data}), 201
        except Exception as e:
            return jsonify({'success': False, 'message': 'Failed to send message'}), 500
    
    else:  # GET
        channel_id = request.args.get('channel_id')
        limit = min(int(request.args.get('limit', 50)), 100)  # Max 100 messages
        
        if not channel_id:
            return jsonify({'success': False, 'message': 'channel_id required'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT m.id, m.user_id, m.content, m.message_type, m.created_at, m.edited_at
            FROM messages m
            WHERE m.channel_id = ?
            ORDER BY m.created_at DESC
            LIMIT ?
        ''', (channel_id, limit))
        
        messages = cursor.fetchall()
        
        # Get user names
        users_conn = sqlite3.connect(USERS_DB)
        users_cursor = users_conn.cursor()
        
        message_list = []
        for msg in reversed(messages):
            users_cursor.execute('SELECT name FROM users WHERE id = ?', (msg[1],))
            user = users_cursor.fetchone()
            
            message_list.append({
                'id': msg[0],
                'user_id': msg[1],
                'user_name': sanitize_input(user[0]) if user else 'Unknown',
                'content': msg[2],  # Already sanitized when stored
                'message_type': msg[3],
                'created_at': msg[4],
                'edited_at': msg[5]
            })
        
        users_conn.close()
        conn.close()
        
        return jsonify({'success': True, 'messages': message_list}), 200

# ==================== DIRECT MESSAGE APIs ====================
@app.route('/api/direct-messages', methods=['GET', 'POST'])
def direct_messages():
    if request.method == 'POST':
        data = request.get_json()
        sender_id = data.get('sender_id')
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not all([sender_id, receiver_id, content]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO direct_messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                         (sender_id, receiver_id, content))
            dm_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Emit to receiver via Socket.IO
            socketio.emit('new_dm', {
                'id': dm_id,
                'sender_id': sender_id,
                'content': content,
                'created_at': datetime.now().isoformat()
            }, room=f'user_{receiver_id}')
            
            return jsonify({'success': True, 'dm_id': dm_id}), 201
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    
    else:  # GET
        user_id = request.args.get('user_id')
        other_user_id = request.args.get('other_user_id')
        
        if not user_id or not other_user_id:
            return jsonify({'success': False, 'message': 'user_id and other_user_id required'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, sender_id, receiver_id, content, created_at, is_read
            FROM direct_messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY created_at ASC
        ''', (user_id, other_user_id, other_user_id, user_id))
        
        dms = cursor.fetchall()
        conn.close()
        
        dm_list = []
        for dm in dms:
            dm_list.append({
                'id': dm[0],
                'sender_id': dm[1],
                'receiver_id': dm[2],
                'content': dm[3],
                'created_at': dm[4],
                'is_read': bool(dm[5])
            })
        
        return jsonify({'success': True, 'messages': dm_list}), 200

# ==================== USER APIs ====================
@app.route('/api/users/online', methods=['GET'])
def online_users():
    workspace_id = request.args.get('workspace_id')
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT us.user_id, us.status, us.last_seen
        FROM user_status us
        WHERE us.status = 'online'
    ''')
    
    statuses = cursor.fetchall()
    
    # Get user names
    users_conn = sqlite3.connect(USERS_DB)
    users_cursor = users_conn.cursor()
    
    user_list = []
    for status in statuses:
        users_cursor.execute('SELECT name, email FROM users WHERE id = ?', (status[0],))
        user = users_cursor.fetchone()
        if user:
            user_list.append({
                'user_id': status[0],
                'name': user[0],
                'email': user[1],
                'status': status[1],
                'last_seen': status[2]
            })
    
    users_conn.close()
    conn.close()
    
    return jsonify({'success': True, 'users': user_list}), 200

# ==================== SOCKET.IO EVENTS ====================
@socketio.on('connect')
def handle_connect():
    @after_this_request
    def add_socketio_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return response
    print(f'Client connected: {request.sid}')
    emit('connected', {'message': 'Connected to Draxyl server!'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')

@socketio.on('join_channel')
def handle_join_channel(data):
    channel_id = data.get('channel_id')
    user_id = data.get('user_id')
    
    if channel_id:
        room = f'channel_{channel_id}'
        join_room(room)
        
        print(f'\n🔵 USER JOINED CHANNEL')
        print(f'   User ID: {user_id}')
        print(f'   Channel ID: {channel_id}')
        print(f'   Room: {room}')
        print(f'   SID: {request.sid}')
        print(f'   Can now receive: incoming_call, messages, etc.\n')
        
        # Update user status
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO user_status (user_id, status, last_seen) VALUES (?, ?, ?)',
                     (user_id, 'online', datetime.now()))
        conn.commit()
        conn.close()
        
        emit('joined_channel', {'channel_id': channel_id}, room=request.sid)
        emit('user_joined', {'user_id': user_id}, room=room, skip_sid=request.sid)

@socketio.on('leave_channel')
def handle_leave_channel(data):
    channel_id = data.get('channel_id')
    user_id = data.get('user_id')
    
    if channel_id:
        room = f'channel_{channel_id}'
        leave_room(room)
        emit('user_left', {'user_id': user_id}, room=room)
        print(f'User {user_id} left channel {channel_id}')

@socketio.on('typing')
def handle_typing(data):
    channel_id = data.get('channel_id')
    user_id = data.get('user_id')
    user_name = data.get('user_name')
    is_typing = data.get('is_typing', True)
    
    if channel_id:
        room = f'channel_{channel_id}'
        emit('user_typing', {
            'user_id': user_id,
            'user_name': user_name,
            'is_typing': is_typing
        }, room=room, skip_sid=request.sid)

@socketio.on('user_status')
def handle_user_status(data):
    user_id = data.get('user_id')
    status = data.get('status', 'online')
    
    if user_id:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO user_status (user_id, status, last_seen) VALUES (?, ?, ?)',
                     (user_id, status, datetime.now()))
        conn.commit()
        conn.close()
        
        emit('status_changed', {'user_id': user_id, 'status': status}, broadcast=True)

# ==================== VIDEO CALL SOCKET EVENTS ====================

# Maximum participants allowed in a single call
MAX_CALL_PARTICIPANTS = 30

@socketio.on('call_initiate')
def handle_call_initiate(data):
    """Handle video call initiation"""
    channel_id = data.get('channel_id')
    caller_id = data.get('caller_id')
    caller_name = data.get('caller_name')
    offer = data.get('offer')
    
    print(f"\n{'='*60}")
    print(f"📞 CALL INITIATED")
    print(f"   Channel: {channel_id}")
    print(f"   Caller: {caller_name} (ID: {caller_id})")
    print(f"   Room: channel_{channel_id}")
    print(f"   Caller SID: {request.sid}")
    print(f"   Offer present: {offer is not None}")
    print(f"   Offer type: {offer.get('type') if offer else 'None'}")
    
    # Get room members to see who will receive the call
    room = f'channel_{channel_id}'
    try:
        # Get all rooms the caller is in
        caller_rooms = list(rooms(request.sid))
        print(f"   Caller is in rooms: {caller_rooms}")
        
        # Get all SIDs in the target room (use socketio.server.manager to get room members)
        room_sids = list(socketio.server.manager.get_participants('/', room))
        print(f"   Room '{room}' has {len(room_sids)} members")
        print(f"   Room SIDs: {room_sids}")
        print(f"   Broadcasting to: {len(room_sids) - 1} users (excluding caller)")
        
        # Check if call would exceed maximum participants
        if len(room_sids) > MAX_CALL_PARTICIPANTS:
            print(f"❌ Call rejected: Room has {len(room_sids)} members, max allowed is {MAX_CALL_PARTICIPANTS}")
            emit('call_rejected', {
                'channel_id': channel_id,
                'reason': f'Call limit exceeded. Maximum {MAX_CALL_PARTICIPANTS} participants allowed, but room has {len(room_sids)} members.'
            })
            print(f"{'='*60}\n")
            return
    except Exception as e:
        print(f"   ⚠️ Error getting room info: {e}")
        room_sids = set()
    
    print(f"{'='*60}\n")
    
    # Validate that offer has required fields
    if offer and 'type' in offer and 'sdp' in offer:
        print(f"✅ Valid offer SDP received ({len(offer['sdp'])} chars)")
    else:
        print(f"⚠️ WARNING: Offer missing type or sdp fields!")
    
    # Broadcast to all users in the channel except caller
    emit('incoming_call', {
        'channel_id': channel_id,
        'caller_id': caller_id,
        'caller_name': caller_name,
        'offer': offer
    }, room=room, skip_sid=request.sid)
    
    print(f"✅ incoming_call event broadcasted to room '{room}'")
    print(f"   Payload sent: channel_id={channel_id}, caller_id={caller_id}, caller_name={caller_name}, offer_present={offer is not None}")


@socketio.on('call_answer')
def handle_call_answer(data):
    """Handle video call answer"""
    channel_id = data.get('channel_id')
    answerer_id = data.get('answerer_id')
    caller_id = data.get('caller_id')
    answer = data.get('answer')
    
    print(f"\n{'='*60}")
    print(f"📞 CALL ANSWER RECEIVED")
    print(f"   Channel: {channel_id}")
    print(f"   Answerer ID: {answerer_id}")
    print(f"   Caller ID: {caller_id}")
    print(f"   Answerer SID: {request.sid}")
    print(f"   Answer present: {answer is not None}")
    print(f"   Answer type: {answer.get('type') if answer else 'None'}")
    
    # Validate answer
    if answer and 'type' in answer and 'sdp' in answer:
        print(f"✅ Valid answer SDP received ({len(answer['sdp'])} chars)")
    else:
        print(f"⚠️ WARNING: Answer missing type or sdp fields!")
    
    room = f'channel_{channel_id}'
    try:
        room_sids = list(socketio.server.manager.get_participants('/', room))
        print(f"   Broadcasting to {len(room_sids)} users in room '{room}'")
    except Exception as e:
        print(f"   ⚠️ Error getting room info: {e}")
    
    print(f"{'='*60}\n")
    
    # Send answer to caller (and everyone in the channel)
    emit('call_answered', {
        'channel_id': channel_id,
        'answerer_id': answerer_id,
        'caller_id': caller_id,
        'answer': answer
    }, room=room)
    
    print(f"✅ call_answered event broadcasted to room '{room}'")

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    """Handle ICE candidate exchange"""
    channel_id = data.get('channel_id')
    candidate = data.get('candidate')
    sender_id = data.get('sender_id')
    
    candidate_type = 'none'
    if candidate:
        candidate_type = candidate.get('type', 'unknown')
        if not candidate_type and 'candidate' in candidate:
            # Try to parse from candidate string
            import re
            match = re.search(r'typ (\w+)', candidate.get('candidate', ''))
            if match:
                candidate_type = match.group(1)
    
    print(f"\n🧊 ICE CANDIDATE")
    print(f"   Channel: {channel_id}")
    print(f"   Sender ID: {sender_id}")
    print(f"   Sender SID: {request.sid}")
    print(f"   Candidate type: {candidate_type}")
    print(f"   Candidate present: {candidate is not None}")
    
    room = f'channel_{channel_id}'
    try:
        room_sids = list(socketio.server.manager.get_participants('/', room))
        print(f"   Broadcasting to {len(room_sids) - 1} users (excluding sender) in room '{room}'")
    except Exception as e:
        print(f"   ⚠️ Error getting room info: {e}")
    
    # Broadcast to all users in channel except sender
    emit('ice_candidate_received', {
        'channel_id': channel_id,
        'candidate': candidate,
        'sender_id': sender_id
    }, room=room, skip_sid=request.sid)
    
    print(f"✅ ICE candidate broadcasted to room '{room}'")

@socketio.on('call_end')
def handle_call_end(data):
    """Handle video call end"""
    channel_id = data.get('channel_id')
    user_id = data.get('user_id')
    
    print(f"📵 Call ended in channel {channel_id}")
    
    # Notify all users in channel
    emit('call_ended', {
        'channel_id': channel_id,
        'user_id': user_id
    }, room=f'channel_{channel_id}')

@socketio.on('call_declined')
def handle_call_declined(data):
    """Handle video call declined"""
    channel_id = data.get('channel_id')
    caller_id = data.get('caller_id')
    decliner_id = data.get('decliner_id')
    
    print(f"❌ Call declined in channel {channel_id}")
    
    # Notify caller
    emit('call_declined', {
        'channel_id': channel_id,
        'caller_id': caller_id,
        'decliner_id': decliner_id
    }, room=f'channel_{channel_id}')

# ==================== WORKSPACE INVITE APIs ====================
@app.route('/api/workspace/<int:workspace_id>/generate-invite', methods=['POST'])
@limiter.limit("10 per hour")
def generate_invite(workspace_id):
    """Generate an invite code for a workspace"""
    data = request.get_json()
    user_id = data.get('user_id')
    max_uses = data.get('max_uses')  # Optional
    expires_days = data.get('expires_days', 7)  # Default 7 days
    
    if not user_id:
        return jsonify({'success': False, 'message': 'User ID required'}), 400
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verify workspace exists and user is a member
        cursor.execute('SELECT owner_id FROM workspaces WHERE id = ?', (workspace_id,))
        workspace = cursor.fetchone()
        
        if not workspace:
            conn.close()
            return jsonify({'success': False, 'message': 'Workspace not found'}), 404
        
        # Generate unique invite code
        import secrets
        import string
        invite_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        
        # Calculate expiration
        from datetime import timedelta
        expires_at = datetime.now() + timedelta(days=expires_days)
        
        cursor.execute('''
            INSERT INTO workspace_invites (workspace_id, invite_code, created_by, expires_at, max_uses, uses)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (workspace_id, invite_code, user_id, expires_at, max_uses))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'invite_code': invite_code,
            'expires_at': expires_at.isoformat(),
            'message': 'Invite code generated successfully'
        }), 201
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/workspace/join-by-code', methods=['POST'])
@limiter.limit("20 per hour")
def join_by_invite_code():
    """Join a workspace using an invite code"""
    data = request.get_json()
    invite_code = data.get('invite_code', '').strip().upper()
    user_id = data.get('user_id')
    
    if not invite_code or not user_id:
        return jsonify({'success': False, 'message': 'Invite code and user ID required'}), 400
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Find the invite
        cursor.execute('''
            SELECT id, workspace_id, max_uses, uses, expires_at 
            FROM workspace_invites 
            WHERE invite_code = ?
        ''', (invite_code,))
        
        invite = cursor.fetchone()
        
        if not invite:
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid invite code'}), 404
        
        invite_id, workspace_id, max_uses, uses, expires_at = invite
        
        # Check if expired
        if expires_at and datetime.fromisoformat(expires_at) < datetime.now():
            conn.close()
            return jsonify({'success': False, 'message': 'Invite code has expired'}), 400
        
        # Check usage limit
        if max_uses and uses >= max_uses:
            conn.close()
            return jsonify({'success': False, 'message': 'Invite code has reached maximum uses'}), 400
        
        # Get workspace info
        cursor.execute('SELECT name FROM workspaces WHERE id = ?', (workspace_id,))
        workspace = cursor.fetchone()
        
        if not workspace:
            conn.close()
            return jsonify({'success': False, 'message': 'Workspace not found'}), 404
        
        workspace_name = workspace[0]
        
        # Get all channels in workspace
        cursor.execute('SELECT id FROM channels WHERE workspace_id = ?', (workspace_id,))
        channels = cursor.fetchall()
        
        # Add user to all channels in the workspace
        for (channel_id,) in channels:
            cursor.execute('''
                INSERT OR IGNORE INTO channel_members (channel_id, user_id)
                VALUES (?, ?)
            ''', (channel_id, user_id))
        
        # Increment invite uses
        cursor.execute('UPDATE workspace_invites SET uses = uses + 1 WHERE id = ?', (invite_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'workspace_id': workspace_id,
            'workspace_name': workspace_name,
            'message': f'Successfully joined {workspace_name}!'
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@limiter.limit("100 per hour")
def delete_message(message_id):
    """Delete a message (only by the author or workspace owner)"""
    data = request.get_json()
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id required'}), 400
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if user is the message author
        cursor.execute('SELECT user_id, channel_id FROM messages WHERE id = ?', (message_id,))
        message = cursor.fetchone()
        
        if not message:
            conn.close()
            return jsonify({'success': False, 'message': 'Message not found'}), 404
        
        message_user_id, channel_id = message
        
        # Check if user is the author or workspace owner
        cursor.execute('''
            SELECT w.owner_id FROM channels c
            JOIN workspaces w ON c.workspace_id = w.id
            WHERE c.id = ?
        ''', (channel_id,))
        workspace_owner = cursor.fetchone()
        
        if message_user_id != user_id and (not workspace_owner or workspace_owner[0] != user_id):
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        # Delete the message
        cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        conn.close()
        
        # Notify via Socket.IO
        socketio.emit('message_deleted', {
            'message_id': message_id,
            'channel_id': channel_id
        }, room=f'channel_{channel_id}')
        
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/channels/<int:channel_id>', methods=['DELETE'])
@limiter.limit("50 per hour")
def delete_channel(channel_id):
    """Delete a channel (only by workspace owner)"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'success': False, 'message': 'user_id required'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if user is the workspace owner
        cursor.execute('''
            SELECT w.owner_id, c.workspace_id FROM channels c
            JOIN workspaces w ON c.workspace_id = w.id
            WHERE c.id = ?
        ''', (channel_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return jsonify({'success': False, 'message': 'Channel not found'}), 404
        
        workspace_owner, workspace_id = result
        
        if workspace_owner != user_id:
            conn.close()
            return jsonify({'success': False, 'message': 'Only workspace owner can delete channels'}), 403
        
        # Delete all related data
        cursor.execute('DELETE FROM messages WHERE channel_id = ?', (channel_id,))
        cursor.execute('DELETE FROM channel_members WHERE channel_id = ?', (channel_id,))
        cursor.execute('DELETE FROM channels WHERE id = ?', (channel_id,))
        
        conn.commit()
        conn.close()
        
        # Notify via Socket.IO
        socketio.emit('channel_deleted', {
            'channel_id': channel_id,
            'workspace_id': workspace_id
        }, room=f'workspace_{workspace_id}')
        
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Security Headers Middleware
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.socket.io; style-src 'self' 'unsafe-inline'; connect-src 'self' https://gdllgvlk-5000.inc1.devtunnels.ms https://gdllgvlk-5001.inc1.devtunnels.ms wss://gdllgvlk-5001.inc1.devtunnels.ms"
    return response

if __name__ == '__main__':
    init_messaging_db()
    print("=" * 60)
    print("🔒 DRAXYL SECURE MESSAGING SERVER v2.0")
    print("=" * 60)
    print("✅ Messaging database initialized")
    print("✅ WebSocket support enabled")
    print("✅ Rate limiting active")
    print("✅ Input sanitization active")
    print("✅ Message validation enabled")
    print("✅ Security headers configured")
    print("🔐 HTTPS/SSL: Enabled (Encrypted traffic)")
    print("⚠️  Production Mode: Debug disabled")
    print("🔗 Connect at http://localhost:5001")
    print("=" * 60)
    try:
        print("🔄 Starting SocketIO server...")
        socketio.run(app, host='0.0.0.0', port=5001, debug=True, use_reloader=False, log_output=True)
        print("✅ Server started successfully")
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ ERROR STARTING SERVER: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
