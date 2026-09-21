"""WSGI entry point: gunicorn -w 2 -t 30 --bind 0.0.0.0:8000 wsgi:app"""
from app import create_app

app = create_app()
