from flask_login import UserMixin      # provides default implementations for user authentication methods (https://www.geeksforgeeks.org/python/how-to-add-authentication-to-your-app-with-flask-login/)
from dateutil.parser import parse      # parses date strings into datetime objects (https://www.geeksforgeeks.org/nlp/nlp-using-dateutil-to-parse-dates/)


# Inherits from UserMixin to integrate with Flask-Login's user session management
class User(UserMixin):
    def __init__(self, id, email, password_hash, is_admin, created_at):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.created_at = created_at

    @staticmethod
    def from_supabase(data):
        created_at = data["created_at"]         # Extracts the 'created_at' field from the Supabase record
        if isinstance(created_at, str):
            created_at = parse(created_at)      # Converts string timestamp to a datetime object using dateutil.parser

        return User(
            id=data["id"],
            email=data["email"],
            password_hash=data["password_hash"],
            is_admin=data["is_admin"],
            created_at=created_at
        )
