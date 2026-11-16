"""
SQL-TRUST Root Scripts Runner for Demo Data Seeder
Delegates to backend/scripts/seed_demo_data.py
"""
import sys
import os

# Delegate to backend.scripts.seed_demo_data
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.scripts.seed_demo_data import seed_demo_data

if __name__ == "__main__":
    success = seed_demo_data()
    sys.exit(0 if success else 1)
