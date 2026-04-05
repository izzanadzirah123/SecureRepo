from app import app
from database import db, User
from werkzeug.security import generate_password_hash

def create_initial_data():
    with app.app_context():
        # Create the database tables
        db.create_all()
        
        # Check if Admin already exists
        if not User.query.filter_by(username="admin").first():
            # Create a default Admin
            hashed_password = generate_password_hash("admin123", method='pbkdf2:sha256')
            new_admin = User(
                username="admin",
                password=hashed_password,
                role="Admin"
            )
            db.session.add(new_admin)
            db.session.commit()
            print("✅ Admin account created: Username: admin, Password: admin123")
        else:
            print("⚠️ Admin account already exists.")

if __name__ == "__main__":
    create_initial_data()