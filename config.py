import os

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database
DATABASE = os.path.join(BASE_DIR, 'database.db')

# Secret keys
SECRET_KEY = 'your-secret-key-123'
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'  # Change this in production!

# WhatsApp settings (Test mode - no real messages sent)
USE_PYWHATKIT = False

# File upload settings
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max

# Points calculation
POINTS_PER_100 = 10
BONUS_500 = 10
BONUS_1000 = 20

# Create necessary folders
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
for folder in [UPLOAD_FOLDER, os.path.join(BASE_DIR, 'static/css')]:
    os.makedirs(folder, exist_ok=True)