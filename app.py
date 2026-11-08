from flask import Flask, render_template, request, jsonify
import os
import database
import scanner

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB file upload

# Initialize SQLite database with table and initial demo records
database.init_db()

@app.route('/')
def index():
    stats = database.get_stats()
    return render_template('index.html', stats=stats)

@app.route('/api/scan-url', methods=['POST'])
def api_scan_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Please enter a website URL or domain name to scan.'}), 400

    try:
        result = scanner.analyze_url(url)
        scan_id = database.save_scan(
            scan_type='url',
            target=url,
            status=result['status'],
            trust_score=result['trust_score'],
            summary=result['summary'],
            details=result
        )
        result['scan_id'] = scan_id
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Scan error: {str(e)}'}), 500

@app.route('/api/scan-message', methods=['POST'])
def api_scan_message():
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Please paste a message or email text to analyze.'}), 400

    try:
        result = scanner.analyze_message(message)
        scan_id = database.save_scan(
            scan_type='message',
            target=result['target'],
            status=result['status'],
            trust_score=result['trust_score'],
            summary=result['summary'],
            details=result
        )
        result['scan_id'] = scan_id
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500

@app.route('/api/scan-file', methods=['POST'])
def api_scan_file():
    # 1. Handle direct file upload
    if 'file' in request.files:
        uploaded_file = request.files['file']
        if uploaded_file.filename == '':
            return jsonify({'error': 'No file selected for analysis.'}), 400
        
        file_bytes = uploaded_file.read()
        filename = uploaded_file.filename
        
        result = scanner.analyze_file_data(file_bytes, filename=filename)
        scan_id = database.save_scan(
            scan_type='file',
            target=filename,
            status=result['status'],
            trust_score=result['trust_score'],
            summary=result['summary'],
            details=result
        )
        result['scan_id'] = scan_id
        return jsonify(result)

    # 2. Handle pasted hash string via JSON
    data = request.get_json(silent=True) or {}
    hash_str = data.get('hash', '').strip()
    if hash_str:
        result = scanner.analyze_hash_string(hash_str)
        scan_id = database.save_scan(
            scan_type='hash',
            target=hash_str,
            status=result['status'],
            trust_score=result['trust_score'],
            summary=result['summary'],
            details=result
        )
        result['scan_id'] = scan_id
        return jsonify(result)

    return jsonify({'error': 'Please provide either a file to upload or a hash string to verify.'}), 400

@app.route('/api/inspect-ssl', methods=['POST'])
def api_inspect_ssl():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Please enter a domain name to inspect SSL/TLS certificates.'}), 400

    try:
        result = scanner.inspect_ssl_domain(domain)
        scan_id = database.save_scan(
            scan_type='ssl',
            target=result['domain'],
            status=result['status'],
            trust_score=result['trust_score'],
            summary=result['summary'],
            details=result
        )
        result['scan_id'] = scan_id
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'SSL inspection error: {str(e)}'}), 500

@app.route('/api/history', methods=['GET'])
def api_history():
    scan_type = request.args.get('type', 'all')
    status = request.args.get('status', 'all')
    search = request.args.get('search', '').strip()
    scans = database.get_recent_scans(limit=30, scan_type=scan_type, status=status, search=search)
    return jsonify({'scans': scans})

@app.route('/api/history/clear', methods=['POST'])
def api_history_clear():
    database.clear_all_scans()
    return jsonify({'success': True, 'message': 'Scan history cleared.'})

@app.route('/api/stats', methods=['GET'])
def api_stats():
    stats = database.get_stats()
    return jsonify(stats)

if __name__ == '__main__':
    # Listen on localhost:5000
    print("=" * 60)
    print(" TRUSTGUARD - AI-Powered Web Threat Detection")
    print(" Digital Trust Intelligence Platform")
    print(" Running at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=True)
