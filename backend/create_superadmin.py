from database.db import SessionLocal, Base, engine
from database import models
from services.auth_service import hash_password

def create_superadmin():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(
            models.User.email == "cboussoura@socilis.com"
        ).first()

        if existing:
            print("✅ Superadmin cboussoura existe déjà.")
            return

        superadmin = models.User(
            email="cboussoura@socilis.com",
            password_hash=hash_password("Passw0rd@2o26"),
            role="superadmin",
            is_active=True
        )
        db.add(superadmin)
        db.commit()
        print("✅ Superadmin cboussoura créé avec succès.")

    except Exception as e:
        db.rollback()
        print(f"❌ Erreur: {e}")

    finally:
        db.close()

if __name__ == "__main__":
    create_superadmin()