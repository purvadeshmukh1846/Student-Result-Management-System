import os

class Config:
    SECRET_KEY = 'your-secret-key-here-change-in-production'
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'your_password_here'  # ← Set your MySQL password here (if any)
    MYSQL_DB = 'srms_db'
    MYSQL_CURSORCLASS = 'DictCursor'