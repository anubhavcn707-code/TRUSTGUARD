import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'trustguard.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            trust_score INTEGER NOT NULL,
            summary TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

    # Seed with a few realistic demonstration examples if empty
    cursor.execute('SELECT COUNT(*) as count FROM scan_history')
    if cursor.fetchone()['count'] == 0:
        samples = [
            (
                'url',
                'https://www.google.com',
                'safe',
                98,
                'Valid SSL certificate from Google Trust Services, secure HTTPS protocol, established domain.',
                json.dumps({
                    'https': True,
                    'ssl_valid': True,
                    'issuer': 'Google Trust Services',
                    'flags': []
                })
            ),
            (
                'message',
                'URGENT: Your bank account will be suspended in 24 hours. Click http://bank-update-auth.com to verify your credentials.',
                'dangerous',
                18,
                'High-risk phishing message detected with artificial urgency and credential harvesting link.',
                json.dumps({
                    'urgency_detected': True,
                    'threat_words': ['urgent', 'suspended', 'verify credentials'],
                    'has_suspicious_link': True
                })
            ),
            (
                'ssl',
                'wikipedia.org',
                'safe',
                95,
                'High-grade TLS encryption active, valid certificate with 200+ days remaining.',
                json.dumps({
                    'issuer': 'Let\'s Encrypt',
                    'protocol': 'TLSv1.3',
                    'days_remaining': 82
                })
            )
        ]
        cursor.executemany('''
            INSERT INTO scan_history (scan_type, target, status, trust_score, summary, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', samples)
        conn.commit()

    conn.close()

def save_scan(scan_type, target, status, trust_score, summary, details):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_history (scan_type, target, status, trust_score, summary, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_type,
        target,
        status,
        trust_score,
        summary,
        json.dumps(details),
        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit=25, scan_type=None, status=None, search=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = 'SELECT * FROM scan_history WHERE 1=1'
    params = []

    if scan_type and scan_type != 'all':
        query += ' AND scan_type = ?'
        params.append(scan_type)

    if status and status != 'all':
        query += ' AND status = ?'
        params.append(status)

    if search:
        query += ' AND (target LIKE ? OR summary LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])

    query += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    results = []
    for row in rows:
        results.append({
            'id': row['id'],
            'scan_type': row['scan_type'],
            'target': row['target'],
            'status': row['status'],
            'trust_score': row['trust_score'],
            'summary': row['summary'],
            'details': json.loads(row['details_json']) if row['details_json'] else {},
            'created_at': row['created_at']
        })
    conn.close()
    return results

def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'safe' THEN 1 ELSE 0 END) as safe_count,
            SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END) as suspicious_count,
            SUM(CASE WHEN status = 'dangerous' THEN 1 ELSE 0 END) as dangerous_count
        FROM scan_history
    ''')
    row = cursor.fetchone()
    stats = {
        'total': row['total'] or 0,
        'safe': row['safe_count'] or 0,
        'suspicious': row['suspicious_count'] or 0,
        'dangerous': row['dangerous_count'] or 0
    }
    conn.close()
    return stats

def clear_all_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_history')
    conn.commit()
    conn.close()
