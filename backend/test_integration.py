import pytest
import os
import sys

# Add backend to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app as flask_app, db, User, ScanHistory

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with flask_app.app_context():
        # Clear Flask-SQLAlchemy engine cache to force using the new in-memory URI
        if 'sqlalchemy' in flask_app.extensions:
            try:
                flask_app.extensions['sqlalchemy']._engines.clear()
            except Exception:
                pass
                
    with flask_app.test_client() as client:
        with flask_app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

def test_full_flow(client):
    # 1. Register User
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password': 'password123',
        'confirm_password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200
    
    # Verify user was created and is admin (first user is admin)
    with flask_app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.is_admin is True

    # 2. Login User
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Threat Intelligence Dashboard" in response.data or b"SOC Dashboard" in response.data

    # 3. Access Dashboard
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b"Terminal Scanner Input" in response.data

    # 4. Analyze URL
    response = client.post('/analyze', data={
        'input_data': 'http://example.com'
    })
    assert response.status_code == 200
    assert b"Scan Results for Indicator" in response.data
    assert b"URL" in response.data

    # 5. Analyze Email
    response = client.post('/analyze', data={
        'input_data': 'URGENT: Verify your bank account credentials now!'
    })
    assert response.status_code == 200
    assert b"Scan Results for Indicator" in response.data
    assert b"EMAIL" in response.data

    # 6. View History
    response = client.get('/history')
    assert response.status_code == 200
    assert b"Investigation Logs" in response.data
    # Check if both items are in history
    assert b"http://example.com" in response.data
    assert b"URGENT: Verify" in response.data

    # 7. View Intel Feed
    response = client.get('/intel')
    assert response.status_code == 200
    assert b"Threat Intelligence Feed" in response.data

    # 8. View Report
    # We should have two scans in DB. Let's query scan ID.
    with flask_app.app_context():
        scan = ScanHistory.query.first()
        assert scan.analyst_report is not None
        assert "attack_type" in scan.analyst_report
        scan_id = scan.id
    
    response = client.get(f'/report/{scan_id}')
    assert response.status_code == 200
    assert b"Threat Investigation Report" in response.data

    # 9. Admin Dashboard
    response = client.get('/admin')
    assert response.status_code == 200
    assert b"Admin Dashboard" in response.data

    # 10. Admin Users
    response = client.get('/admin/users')
    assert response.status_code == 200
    assert b"User Management" in response.data

    # 11. Admin History
    response = client.get('/admin/history')
    assert response.status_code == 200
    assert b"Global Audit Logs" in response.data

    # 12. QR Code API Scan (capitalized URL protocol check)
    response = client.post('/scan', json={
        'input': 'HTTPS://PAYPAL-SECURE-LOGIN.NET'
    })
    assert response.status_code == 200
    qr_data = response.get_json()
    assert qr_data['scan_type'] == 'URL'
    assert qr_data['risk'] > 25
    assert 'analyst_report' in qr_data
    assert qr_data['analyst_report']['attack_type'] is not None

    # 13. Screenshot Detector Scan (Visual OCR & CV logic check)
    import io
    from PIL import Image as PILImage
    img = PILImage.new('RGB', (100, 100), color='red')
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)
    
    response = client.post('/screenshot-detector', data={
        'screenshot': (img_byte_arr, 'test_screenshot.png')
    }, content_type='multipart/form-data')
    assert response.status_code == 200
    ss_data = response.get_json()
    assert ss_data['status'] == 'SUCCESS'
    assert ss_data['scam_verdict'] in ['SAFE', 'LOW RISK', 'SUSPICIOUS', 'HIGH RISK', 'MALICIOUS']
    assert 'ai_critique' in ss_data
    assert 'analyst_report' in ss_data
    assert ss_data['analyst_report']['attack_type'] is not None
