# models.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import uuid

db = SQLAlchemy()

def generate_uuid():
    """Generates a random UUID string."""
    return str(uuid.uuid4())

class QuantumKey(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    key_data = db.Column(db.LargeBinary, nullable=False)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f'<Key {self.id}>'