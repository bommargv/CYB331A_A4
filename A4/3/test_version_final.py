import tempfile
from version_final import create_app

def test_logout_csrf_blocked():
    db_file = tempfile.NamedTemporaryFile(delete=False)

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "A" * 32,
        "DATABASE": db_file.name,
    })

    client = app.test_client()

    # Register user
    client.post(
        "/register",
        json={
            "username": "testuser",
            "password": "StrongPass123!"
        }
    )

    # Login user
    login_resp = client.post(
        "/login",
        json={
            "username": "testuser",
            "password": "StrongPass123!"
        }
    )

    assert login_resp.status_code == 200

    # Simulated CSRF attack:
    # POST without X-CSRF-Token header
    attack_resp = client.post("/logout")

    assert attack_resp.status_code == 403
    assert attack_resp.json["error"] == "CSRF validation failed."

    print("PASS: CSRF attack blocked")

if __name__ == "__main__":
    test_logout_csrf_blocked()