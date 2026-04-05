from app import app, db, User
from werkzeug.security import generate_password_hash
import os
import pyotp

def reset():
    with app.app_context():
        # 1. Delete the old database file if it exists
        db_path = 'instance/secure_repo.db'
        if os.path.exists(db_path):
            os.remove(db_path)
            print("Old database deleted.")

        # 2. Create all tables
        db.create_all()

        # 3. Create a fresh Admin user
        admin = User(
            username="admin",
            password=generate_password_hash("admin123"),
            role="Admin",
            mfa_secret=pyotp.random_base32()
        )

        # 4. Create a fresh Trainer user
        trainer = User(
            username="trainer",
            password=generate_password_hash("trainer123"),
            role="Trainer",
            mfa_secret=pyotp.random_base32()
        )

        db.session.add(admin)
        db.session.add(trainer)
        db.session.commit()

        print(f"Database Reset Successful!")
        print(f"Admin Login: admin / admin123 | Secret: {admin.mfa_secret}")
        print(f"Trainer Login: trainer / trainer123 | Secret: {trainer.mfa_secret}")

if __name__ == "__main__":
    reset()