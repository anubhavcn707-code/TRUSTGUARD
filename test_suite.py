"""
TRUSTGUARD - Automated Verification & Demonstration Test Suite
Run this file to verify backend APIs, database persistence, and security engines.
Command: python test_suite.py
"""

import io
import unittest
import app
import scanner
import database

class TestTrustGuard(unittest.TestCase):

    def setUp(self):
        self.client = app.app.test_client()

    def test_01_home_page(self):
        """Verify main web interface loads successfully"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'TRUSTGUARD', response.data)
        self.assertIn(b'AI-Powered Web Threat Detection', response.data)
        print(' [PASS] Home Page & UI template loaded')

    def test_02_url_scanner_safe_and_phishing(self):
        """Verify URL threat detection logic"""
        # Phishing check (unencrypted, multiple hyphens, high-risk keywords, .xyz)
        phish_url = 'http://paypal-verification-account-security-update.xyz/login'
        result = scanner.analyze_url(phish_url)
        self.assertIn(result['status'], ['suspicious', 'dangerous'])
        self.assertLess(result['trust_score'], 60)
        print(f' [PASS] URL Phishing detection: Status={result["status"].upper()} (Score: {result["trust_score"]})')

        # Raw IP check
        ip_url = 'http://192.168.1.1/admin'
        res_ip = scanner.analyze_url(ip_url)
        self.assertTrue(res_ip['details']['is_ip_address'])
        print(f' [PASS] Raw IP URL detection: HostType={res_ip["details"]["ip_type"]}')

    def test_03_message_detector(self):
        """Verify rule-based scam and phishing message detection"""
        scam_text = 'URGENT: Your Netflix account has been suspended. Update billing within 24 hours at http://netflix-billing.xyz'
        res_scam = scanner.analyze_message(scam_text)
        self.assertIn(res_scam['status'], ['suspicious', 'dangerous'])
        self.assertTrue(len(res_scam['threat_flags']) >= 2)
        print(f' [PASS] Scam Message detection: Status={res_scam["status"].upper()} (Triggers: {len(res_scam["threat_flags"])})')

        # Safe message
        safe_text = 'Hi Sarah, are we meeting at the university library today at 4 PM for the project review?'
        res_safe = scanner.analyze_message(safe_text)
        self.assertEqual(res_safe['status'], 'safe')
        self.assertEqual(res_safe['trust_score'], 100)
        print(' [PASS] Normal clean message verified: Score=100 (SAFE)')

    def test_04_file_and_hash_checker(self):
        """Verify cryptographic hash calculations (hashlib) and known threat detection"""
        # Test known malicious hash (EICAR)
        res_hash = scanner.analyze_hash_string('44d88612fea8a8f36de82e1278abb02f')
        self.assertEqual(res_hash['status'], 'dangerous')
        self.assertEqual(res_hash['trust_score'], 0)
        print(' [PASS] Known malware signature detected via hashlib')

        # Test safe file upload
        test_file = (io.BytesIO(b'Clean college cybersecurity report text.'), 'report.pdf')
        res_upload = self.client.post('/api/scan-file', data={'file': test_file}, content_type='multipart/form-data')
        self.assertEqual(res_upload.status_code, 200)
        data = res_upload.get_json()
        self.assertEqual(data['status'], 'safe')
        self.assertIn('sha256', data)
        print(f' [PASS] Safe file upload: SHA256={data["sha256"][:16]}...')

    def test_05_database_audit_logs(self):
        """Verify SQLite audit logging and retrieval"""
        stats = database.get_stats()
        self.assertGreater(stats['total'], 0)
        print(f' [PASS] Database Persistence: {stats["total"]} total scans recorded in SQLite')

if __name__ == '__main__':
    print('=' * 60)
    print(' TRUSTGUARD TEST SUITE - CYBERSECURITY ENGINE VERIFICATION')
    print('=' * 60)
    unittest.main()
