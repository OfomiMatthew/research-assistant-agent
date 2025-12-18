from flask import Flask, render_template, request, jsonify, send_file, session
from groq import Groq
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import json
from datetime import datetime, timedelta
import io
import uuid

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

DB_PATH = "research_assistant.db"

RESEARCH_MODES = {
    "general": {
        "name": "General Research",
        "description": "Comprehensive research analysis and synthesis",
        "icon": "🔍",
        "prompt": """You are an expert AI research assistant. Your role is to help researchers, academics, and professionals by:
1. Analyzing complex research questions and providing comprehensive answers
2. Synthesizing information from multiple perspectives
3. Identifying research gaps and suggesting new directions
4. Explaining technical concepts clearly
5. Providing citations and references when relevant
6. Critically evaluating claims and evidence
7. Helping with literature reviews and research design

Provide detailed, well-structured responses that are informative and actionable."""
    },
    "literature": {
        "name": "Literature Review",
        "description": "Specialized for comprehensive literature analysis",
        "icon": "📚",
        "prompt": """You are an expert literature review assistant. Your specialized role is to:
1. Analyze and synthesize academic papers and sources
2. Identify research trends and patterns in literature
3. Highlight gaps in existing research
4. Compare different methodological approaches
5. Categorize findings by themes and concepts
6. Provide structured summaries of research areas
7. Suggest seminal works and influential papers
8. Create comprehensive literature maps and taxonomies

Format responses with clear structure, include bibliographic references, and organize information thematically."""
    },
    "methodology": {
        "name": "Research Methodology",
        "description": "Focuses on research design and methods",
        "icon": "⚙️",
        "prompt": """You are an expert research methodology consultant. Your specialized role is to:
1. Help design robust research methodologies
2. Evaluate research designs for validity and reliability
3. Suggest appropriate statistical methods and analytical approaches
4. Identify potential biases and limitations
5. Provide guidance on data collection and analysis
6. Help troubleshoot methodological challenges
7. Compare different research paradigms and approaches
8. Ensure methodological rigor and reproducibility

Provide actionable recommendations grounded in research best practices."""
    },
    "data_analysis": {
        "name": "Data Analysis",
        "description": "Specialized for data interpretation and insights",
        "icon": "📊",
        "prompt": """You are an expert data analysis assistant. Your specialized role is to:
1. Help interpret complex datasets and research findings
2. Suggest appropriate analytical techniques
3. Identify patterns, trends, and anomalies
4. Explain statistical concepts and results clearly
5. Help validate research conclusions
6. Suggest alternative analytical approaches
7. Identify potential data quality issues
8. Provide insights for evidence-based decision making

Provide clear, data-driven explanations with actionable insights."""
    },
    "writing": {
        "name": "Academic Writing",
        "description": "Help with research writing and presentation",
        "icon": "✍️",
        "prompt": """You are an expert academic writing coach. Your specialized role is to:
1. Help structure research papers and theses
2. Improve clarity and coherence in academic writing
3. Suggest ways to strengthen arguments with evidence
4. Help develop compelling research narratives
5. Provide guidance on academic conventions and standards
6. Help with literature integration and citation practices
7. Suggest ways to make writing more concise and impactful
8. Help prepare manuscripts for publication

Provide constructive feedback and actionable writing suggestions."""
    }
}

AVAILABLE_MODELS = {
    "llama-3.3-70b-versatile": {
        "name": "Llama 3.3 70B (Recommended)",
        "speed": "Fast",
        "capability": "Excellent"
    },
    "llama-3.1-8b-instant": {
        "name": "Llama 3.1 8B (Fast & Compact)",
        "speed": "Very Fast",
        "capability": "Good"
    }
}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP,
        preferences TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT,
        data TEXT,
        created_at TIMESTAMP,
        updated_at TIMESTAMP,
        tags TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS bookmarks (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        prompt TEXT NOT NULL,
        title TEXT,
        mode TEXT,
        created_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP,
        created_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS analytics (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        model TEXT,
        mode TEXT,
        tokens_used INTEGER,
        response_time_ms INTEGER,
        created_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (conversation_id) REFERENCES conversations (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS feedback (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        message_index INTEGER,
        rating INTEGER,
        feedback_text TEXT,
        created_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (conversation_id) REFERENCES conversations (id)
    )''')
    
    conn.commit()
    conn.close()

init_db()

def get_user_from_session():
    if 'user_id' not in session:
        return None
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, email, preferences FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'preferences': json.loads(user[3]) if user[3] else {}
        }
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not email or not password:
            return jsonify({'error': 'All fields required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            user_id = str(uuid.uuid4())
            c.execute('''INSERT INTO users (id, username, email, password, created_at, preferences) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (user_id, username, email, generate_password_hash(password), datetime.now(), 
                       json.dumps({'theme': 'light', 'model': 'llama-3.3-70b-versatile', 'mode': 'general'})))
            conn.commit()
            
            session['user_id'] = user_id
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': email
                }
            }), 201
        
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists'}), 409
        finally:
            conn.close()
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, password, email, preferences FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if not user or not check_password_hash(user[1], password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        session['user_id'] = user[0]
        
        return jsonify({
            'success': True,
            'user': {
                'id': user[0],
                'username': username,
                'email': user[2],
                'preferences': json.loads(user[3]) if user[3] else {}
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'success': True})

@app.route('/api/auth/check', methods=['GET'])
def check_auth():
    user = get_user_from_session()
    if user:
        return jsonify({'authenticated': True, 'user': user})
    return jsonify({'authenticated': False})

@app.route('/api/modes', methods=['GET'])
def get_modes():
    return jsonify({
        'modes': {k: {'name': v['name'], 'description': v['description'], 'icon': v['icon']} 
                  for k, v in RESEARCH_MODES.items()}
    })

@app.route('/api/models', methods=['GET'])
def get_models():
    return jsonify({'models': AVAILABLE_MODELS})

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        user = get_user_from_session()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.json
        user_message = data.get('message', '').strip()
        model = data.get('model', 'llama-3.3-70b-versatile')
        mode = data.get('mode', 'general')
        conversation_id = data.get('conversation_id')
        
        if not user_message or len(user_message) < 2:
            return jsonify({'error': 'Message must be at least 2 characters'}), 400
        if len(user_message) > 10000:
            return jsonify({'error': 'Message is too long (max 10000 characters)'}), 400
        
        if mode not in RESEARCH_MODES:
            return jsonify({'error': 'Invalid research mode'}), 400
        
        if model not in AVAILABLE_MODELS:
            return jsonify({'error': 'Invalid model'}), 400
        
        system_prompt = RESEARCH_MODES[mode]['prompt']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        if conversation_id:
            c.execute('SELECT data FROM conversations WHERE id = ? AND user_id = ?', 
                     (conversation_id, user['id']))
            conv = c.fetchone()
            if conv:
                conversation_history = json.loads(conv[0])
            else:
                return jsonify({'error': 'Conversation not found'}), 404
        else:
            conversation_history = []
            conversation_id = str(uuid.uuid4())
        
        conversation_history.append({"role": "user", "content": user_message})
        
        import time
        start_time = time.time()
        
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                *conversation_history
            ],
            temperature=0.7,
            max_tokens=2048,
        )
        
        response_time_ms = int((time.time() - start_time) * 1000)
        assistant_message = response.choices[0].message.content
        tokens_used = response.usage.total_tokens if hasattr(response, 'usage') else 0
        
        conversation_history.append({"role": "assistant", "content": assistant_message})
        
        title = user_message[:50] + "..." if len(user_message) > 50 else user_message
        c.execute('''INSERT OR REPLACE INTO conversations (id, user_id, title, data, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (conversation_id, user['id'], title, json.dumps(conversation_history), 
                   datetime.now(), datetime.now()))
        
        analytics_id = str(uuid.uuid4())
        c.execute('''INSERT INTO analytics (id, user_id, conversation_id, model, mode, tokens_used, response_time_ms, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (analytics_id, user['id'], conversation_id, model, mode, tokens_used, response_time_ms, datetime.now()))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'response': assistant_message,
            'conversation_id': conversation_id,
            'mode': mode,
            'model': model,
            'tokens_used': tokens_used,
            'response_time_ms': response_time_ms
        })
    
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/api/bookmarks', methods=['GET'])
def get_bookmarks():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, prompt, title, mode, created_at FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC',
              (user['id'],))
    bookmarks = [{'id': row[0], 'prompt': row[1], 'title': row[2], 'mode': row[3], 'created_at': row[4]}
                 for row in c.fetchall()]
    conn.close()
    
    return jsonify({'bookmarks': bookmarks})

@app.route('/api/bookmarks', methods=['POST'])
def add_bookmark():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    prompt = data.get('prompt', '').strip()
    title = data.get('title', '').strip()
    mode = data.get('mode', 'general')
    
    if not prompt:
        return jsonify({'error': 'Prompt required'}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    bookmark_id = str(uuid.uuid4())
    c.execute('''INSERT INTO bookmarks (id, user_id, prompt, title, mode, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (bookmark_id, user['id'], prompt, title or prompt[:30], mode, datetime.now()))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'bookmark_id': bookmark_id}), 201

@app.route('/api/bookmarks/<bookmark_id>', methods=['DELETE'])
def delete_bookmark(bookmark_id):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM bookmarks WHERE id = ? AND user_id = ?', (bookmark_id, user['id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/conversations', methods=['GET'])
def get_conversations():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    search_query = request.args.get('search', '').strip().lower()
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if search_query:
        c.execute('''SELECT id, title, created_at, updated_at FROM conversations 
                     WHERE user_id = ? AND (title LIKE ? OR data LIKE ?)
                     ORDER BY updated_at DESC LIMIT 50''',
                  (user['id'], f'%{search_query}%', f'%{search_query}%'))
    else:
        c.execute('SELECT id, title, created_at, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC LIMIT 20',
                  (user['id'],))
    
    conversations = [{'id': row[0], 'title': row[1], 'created_at': row[2], 'updated_at': row[3]}
                     for row in c.fetchall()]
    conn.close()
    
    return jsonify({'conversations': conversations})

@app.route('/api/conversations/<conversation_id>', methods=['GET'])
def get_conversation(conversation_id):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT data, title FROM conversations WHERE id = ? AND user_id = ?', 
              (conversation_id, user['id']))
    conv = c.fetchone()
    conn.close()
    
    if not conv:
        return jsonify({'error': 'Conversation not found'}), 404
    
    return jsonify({'history': json.loads(conv[0]), 'title': conv[1]})

@app.route('/api/export', methods=['GET'])
def export_conversation():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        conversation_id = request.args.get('id')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT data, title FROM conversations WHERE id = ? AND user_id = ?',
                  (conversation_id, user['id']))
        conv = c.fetchone()
        conn.close()
        
        if not conv:
            return jsonify({'error': 'Conversation not found'}), 404
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'title': conv[1],
            'conversation': json.loads(conv[0])
        }
        
        output = io.BytesIO()
        output.write(json.dumps(export_data, indent=2).encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'research_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/preferences', methods=['PUT'])
def update_preferences():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        preferences = data.get('preferences', {})
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE users SET preferences = ? WHERE id = ?',
                  (json.dumps(preferences), user['id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/conversations/<conversation_id>', methods=['DELETE'])
def delete_conversation(conversation_id):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM conversations WHERE id = ? AND user_id = ?', (conversation_id, user['id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/conversations/<conversation_id>/share', methods=['POST'])
def share_conversation(conversation_id):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT data, title FROM conversations WHERE id = ? AND user_id = ?', 
              (conversation_id, user['id']))
    conv = c.fetchone()
    
    if not conv:
        conn.close()
        return jsonify({'error': 'Conversation not found'}), 404
    
    share_id = str(uuid.uuid4())[:8]
    share_data = {
        'id': share_id,
        'conversation_id': conversation_id,
        'user_id': user['id'],
        'title': conv[1],
        'created_at': datetime.now().isoformat()
    }
    
    c.execute('''CREATE TABLE IF NOT EXISTS shared_conversations (
        id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        share_data TEXT
    )''')
    
    c.execute('INSERT OR REPLACE INTO shared_conversations (id, conversation_id, user_id, share_data) VALUES (?, ?, ?, ?)',
              (share_id, conversation_id, user['id'], json.dumps(share_data)))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'share_id': share_id})

@app.route('/api/user/profile', methods=['PUT'])
def update_profile():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        new_username = data.get('username', '').strip()
        new_email = data.get('email', '').strip()
        new_password = data.get('password', '').strip()
        
        if new_username and (len(new_username) < 3 or len(new_username) > 50):
            return jsonify({'error': 'Username must be 3-50 characters'}), 400
        
        if new_email and '@' not in new_email:
            return jsonify({'error': 'Invalid email format'}), 400
        
        if new_password and len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        if new_password:
            c.execute('UPDATE users SET password = ? WHERE id = ?',
                      (generate_password_hash(new_password), user['id']))
        
        if new_username and new_username != user['username']:
            try:
                c.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user['id']))
            except sqlite3.IntegrityError:
                conn.close()
                return jsonify({'error': 'Username already taken'}), 409
        
        if new_email and new_email != user['email']:
            try:
                c.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user['id']))
            except sqlite3.IntegrityError:
                conn.close()
                return jsonify({'error': 'Email already in use'}), 409
        
        conn.commit()
        
        c.execute('SELECT username, email, preferences FROM users WHERE id = ?', (user['id'],))
        updated = c.fetchone()
        conn.close()
        
        session['user_id'] = user['id']
        session.permanent = True
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'username': updated[0],
                'email': updated[1],
                'preferences': json.loads(updated[2]) if updated[2] else {}
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/conversations/<conversation_id>/rename', methods=['PUT'])
def rename_conversation(conversation_id):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        new_title = data.get('title', '').strip()
        
        if not new_title or len(new_title) < 1 or len(new_title) > 200:
            return jsonify({'error': 'Title must be 1-200 characters'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE conversations SET title = ? WHERE id = ? AND user_id = ?',
                  (new_title, conversation_id, user['id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''SELECT COUNT(*), SUM(tokens_used), AVG(response_time_ms) 
                 FROM analytics WHERE user_id = ?''', (user['id'],))
    stats = c.fetchone()
    
    c.execute('''SELECT model, COUNT(*) as count FROM analytics 
                 WHERE user_id = ? GROUP BY model''', (user['id'],))
    models = [{'model': row[0], 'count': row[1]} for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({
        'total_requests': stats[0] or 0,
        'total_tokens': stats[1] or 0,
        'avg_response_time_ms': round(stats[2]) if stats[2] else 0,
        'models_used': models
    })

@app.route('/api/conversations/<conversation_id>/feedback', methods=['POST'])
def add_feedback(conversation_id):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        rating = data.get('rating')
        feedback_text = data.get('feedback', '').strip()
        message_index = data.get('message_index', 0)
        
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify({'error': 'Rating must be 1-5'}), 400
        
        if len(feedback_text) > 1000:
            return jsonify({'error': 'Feedback is too long'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id FROM conversations WHERE id = ? AND user_id = ?',
                  (conversation_id, user['id']))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': 'Conversation not found'}), 404
        
        feedback_id = str(uuid.uuid4())
        c.execute('''INSERT INTO feedback (id, user_id, conversation_id, message_index, rating, feedback_text, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (feedback_id, user['id'], conversation_id, message_index, rating, feedback_text, datetime.now()))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'feedback_id': feedback_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
