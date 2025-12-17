#!/usr/bin/env python3
import subprocess
import sys
import os

def install_requirements():
    """Install required packages"""
    print("📦 Installing requirements...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def check_requirements():
    """Check if requirements are installed"""
    try:
        import flask
        import pandas
        import gunicorn
        return True
    except ImportError:
        return False

def create_folders():
    """Create necessary folders"""
    folders = ['uploads', 'templates', 'static/css', 'static/js', 'static/images']
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"📁 Created folder: {folder}")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 Technician Loyalty System Setup")
    print("="*60)
    
    create_folders()
    
    if not check_requirements():
        print("⚠️ Requirements not found. Installing...")
        install_requirements()
    
    print("\n✅ Starting the application...")
    print("="*60)
    
    # Import only after installing requirements
    from app import app
    
    # Check if running in production (Render sets PORT)
    port = int(os.environ.get('PORT', 5000))
    
    print(f"\n🌐 Server running on port {port}")
    print("📱 WhatsApp messages are simulated in console")
    print("="*60)
    
    # Run with gunicorn in production, Flask dev server locally
    if os.environ.get('RENDER'):
        from gunicorn.app.base import BaseApplication
        
        class FlaskApplication(BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()
            
            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key, value)
            
            def load(self):
                return self.application
        
        options = {
            'bind': f'0.0.0.0:{port}',
            'workers': 2,
            'timeout': 120,
            'keepalive': 5
        }
        
        FlaskApplication(app, options).run()
    else:
        # Local development
        app.run(debug=True, host='0.0.0.0', port=port)
