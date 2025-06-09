import psycopg2
import psycopg2.extras
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
import bcrypt

class DatabaseManager:
    def __init__(self):
        # Database connection parameters - use environment variables in production
        self.connection_params = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'database': os.getenv('DB_NAME', 'nufitcheck'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD', 'password'),
            'port': os.getenv('DB_PORT', '5432')
        }
        self.connection = None

    def connect(self):
        """Establish database connection"""
        try:
            if self.connection and not self.connection.closed:
                return True
                
            self.connection = psycopg2.connect(**self.connection_params)
            self.connection.autocommit = True
            return True
        except Exception as e:
            print(f"Error connecting to database: {e}")
            return False

    def close(self):
        """Close database connection"""
        if self.connection and not self.connection.closed:
            self.connection.close()

    def init_db(self):
        """Initialize database tables"""
        if not self.connect():
            raise Exception("Failed to connect to database")

        try:
            cursor = self.connection.cursor()
            
            # Create auth_users table for authentication
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Create users table (keeping existing structure)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email) REFERENCES auth_users(email) ON DELETE CASCADE
                )
            """)
            
            # Create scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    video_path TEXT,
                    image_paths JSONB,
                    score INTEGER,
                    feedback TEXT
                )
            """)
            
            # Create chat_history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS chat_history (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Updated: Create password_reset_codes table (changed from tokens to codes)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_codes (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) NOT NULL,
                    code VARCHAR(4) NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email) REFERENCES auth_users(email) ON DELETE CASCADE
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_chat_history_scan_id ON chat_history(scan_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_password_reset_codes_code ON password_reset_codes(code);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_password_reset_codes_email ON password_reset_codes(email);
            """)
            
            cursor.close()
            print("Database tables initialized successfully")
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            raise

    # Authentication methods
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            print(f"Error verifying password: {e}")
            return False

    def create_auth_user(self, email: str, password: str) -> bool:
        """Create a new authenticated user"""
        try:
            if not self.connect():
                return False
                
            cursor = self.connection.cursor()
            password_hash = self.hash_password(password)
            
            cursor.execute(
                "INSERT INTO auth_users (email, password_hash) VALUES (%s, %s)",
                (email.lower(), password_hash)
            )
            cursor.close()
            print(f"Auth user {email} created successfully")
            return True
            
        except psycopg2.IntegrityError as e:
            print(f"User with email {email} already exists: {e}")
            return False
        except Exception as e:
            print(f"Error creating auth user: {e}")
            return False

    def authenticate_user(self, email: str, password: str) -> Optional[Dict]:
        """Authenticate user with email and password"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM auth_users WHERE email = %s AND is_active = TRUE",
                (email.lower(),)
            )
            user = cursor.fetchone()
            cursor.close()
            
            if user and self.verify_password(password, user['password_hash']):
                return {
                    'id': user['id'],
                    'email': user['email'],
                    'created_at': user['created_at'],
                    'is_active': user['is_active']
                }
            return None
            
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return None

    def get_auth_user_by_email(self, email: str) -> Optional[Dict]:
        """Get authenticated user by email"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM auth_users WHERE email = %s AND is_active = TRUE",
                (email.lower(),)
            )
            user = cursor.fetchone()
            cursor.close()
            
            return dict(user) if user else None
            
        except Exception as e:
            print(f"Error getting auth user: {e}")
            return None

    def update_password(self, email: str, new_password: str) -> bool:
        """Update user password"""
        try:
            if not self.connect():
                return False
                
            cursor = self.connection.cursor()
            password_hash = self.hash_password(new_password)
            
            cursor.execute(
                "UPDATE auth_users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE email = %s",
                (password_hash, email.lower())
            )
            
            success = cursor.rowcount > 0
            cursor.close()
            
            if success:
                print(f"Password updated for user {email}")
            return success
            
        except Exception as e:
            print(f"Error updating password: {e}")
            return False
        # Add this new method to your DatabaseManager class in database.py

    def verify_password_reset_code_for_email(self, email: str, code: str) -> Optional[str]:
        """Verify password reset code for a specific email"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor()
            # Check code exists, is not used, not expired, and belongs to the email
            cursor.execute(
                """SELECT email, code, expires_at, used 
                FROM password_reset_codes 
                WHERE email = %s AND code = %s AND used = FALSE AND expires_at > (NOW() AT TIME ZONE 'UTC')""",
                (email.lower(), code)
            )
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                print(f"Valid password reset code found for email: {result[0]}")
                return result[0]
            else:
                print(f"Invalid or expired password reset code: {code} for email: {email}")
                return None
                
        except Exception as e:
            print(f"Error verifying password reset code for email: {e}")
            return None

    def mark_code_as_used_for_email(self, email: str, code: str) -> bool:
        """Mark password reset code as used for specific email"""
        try:
            if not self.connect():
                return False
                
            cursor = self.connection.cursor()
            cursor.execute(
                "UPDATE password_reset_codes SET used = TRUE WHERE email = %s AND code = %s",
                (email.lower(), code)
            )
            success = cursor.rowcount > 0
            cursor.close()
            
            if success:
                print(f"Password reset code marked as used: {code} for email: {email}")
            return success
            
        except Exception as e:
            print(f"Error marking code as used for email: {e}")
            return False

    def get_active_reset_codes_count(self, email: str) -> int:
        """Get count of active reset codes for an email"""
        try:
            if not self.connect():
                return 0
                
            cursor = self.connection.cursor()
            cursor.execute(
                """SELECT COUNT(*) FROM password_reset_codes 
                WHERE email = %s AND used = FALSE AND expires_at > (NOW() AT TIME ZONE 'UTC')""",
                (email.lower(),)
            )
            count = cursor.fetchone()[0]
            cursor.close()
            
            return count
            
        except Exception as e:
            print(f"Error getting active reset codes count: {e}")
            return 0

    def cleanup_codes_for_email(self, email: str):
        """Clean up all codes (used and expired) for a specific email"""
        try:
            if not self.connect():
                return 0
                
            cursor = self.connection.cursor()
            cursor.execute(
                "DELETE FROM password_reset_codes WHERE email = %s AND (expires_at < CURRENT_TIMESTAMP OR used = TRUE)",
                (email.lower(),)
            )
            deleted_count = cursor.rowcount
            cursor.close()
            
            print(f"Cleaned up {deleted_count} codes for email: {email}")
            return deleted_count
            
        except Exception as e:
            print(f"Error cleaning up codes for email: {e}")
            return 0
    # Updated: Password reset code methods (changed from token to code)
    def create_password_reset_code(self, email: str, code: str, expires_at: datetime) -> bool:
        """Create password reset code"""
        try:
            if not self.connect():
                return False
                
            cursor = self.connection.cursor()
            # First, delete any existing unused codes for this email
            cursor.execute(
                "DELETE FROM password_reset_codes WHERE email = %s AND used = FALSE",
                (email.lower(),)
            )
            
            # Insert new code - ensure expires_at is in UTC
            cursor.execute(
                "INSERT INTO password_reset_codes (email, code, expires_at) VALUES (%s, %s, %s AT TIME ZONE 'UTC')",
                (email.lower(), code, expires_at)
            )
            cursor.close()
            print(f"Password reset code created for {email}")
            return True
            
        except Exception as e:
            print(f"Error creating password reset code: {e}")
            return False

    def verify_password_reset_code(self, code: str) -> Optional[str]:
        """Verify password reset code and return email if valid"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor()
            # FIX: Use timezone-aware comparison
            cursor.execute(
                """SELECT email, code, expires_at, used 
                FROM password_reset_codes 
                WHERE code = %s AND used = FALSE AND expires_at > (NOW() AT TIME ZONE 'UTC')""",
                (code,)
            )
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                print(f"Valid password reset code found for email: {result[0]}")
                return result[0]
            else:
                print(f"Invalid or expired password reset code: {code}")
                return None
                
        except Exception as e:
            print(f"Error verifying password reset code: {e}")
            return None

    def mark_code_as_used(self, code: str) -> bool:
        """Mark password reset code as used"""
        try:
            if not self.connect():
                return False
                
            cursor = self.connection.cursor()
            cursor.execute(
                "UPDATE password_reset_codes SET used = TRUE WHERE code = %s",
                (code,)
            )
            success = cursor.rowcount > 0
            cursor.close()
            
            if success:
                print(f"Password reset code marked as used: {code}")
            return success
            
        except Exception as e:
            print(f"Error marking code as used: {e}")
            return False

    def cleanup_expired_codes(self):
        """Remove expired or used password reset codes"""
        try:
            if not self.connect():
                return 0
                
            cursor = self.connection.cursor()
            cursor.execute(
                "DELETE FROM password_reset_codes WHERE expires_at < CURRENT_TIMESTAMP OR used = TRUE"
            )
            deleted_count = cursor.rowcount
            cursor.close()
            
            print(f"Cleaned up {deleted_count} expired/used password reset codes")
            return deleted_count
            
        except Exception as e:
            print(f"Error cleaning up codes: {e}")
            return 0

    # Keep existing methods for outfit analysis functionality
    def create_user(self, user_id: str, email: str = None) -> bool:
        """Create a new user (for outfit analysis)"""
        try:
            if not self.connect():
                return False
                
            cursor = self.connection.cursor()
            cursor.execute(
                "INSERT INTO users (id, email) VALUES (%s, %s)",
                (user_id, email.lower() if email else None)
            )
            cursor.close()
            print(f"User {user_id} created successfully")
            return True
            
        except Exception as e:
            print(f"Error creating user: {e}")
            return False

    def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM users WHERE id = %s",
                (user_id,)
            )
            user = cursor.fetchone()
            cursor.close()
            return dict(user) if user else None
            
        except Exception as e:
            print(f"Error getting user: {e}")
            return None

    def create_scan(self, scan_id: str, user_id: str, video_path: str, 
                   image_paths: List[str], score: Optional[int], feedback: str) -> bool:
        """Create a new scan"""
        try:
            if not self.connect():
                print(f"Failed to connect to database for scan {scan_id}")
                return False
                
            cursor = self.connection.cursor()
            cursor.execute(
                """INSERT INTO scans (id, user_id, video_path, image_paths, score, feedback) 
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (scan_id, user_id, video_path, json.dumps(image_paths), score, feedback)
            )
            cursor.close()
            print(f"Scan {scan_id} created successfully")
            return True
            
        except Exception as e:
            print(f"Error creating scan {scan_id}: {e}")
            return False

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM scans WHERE id = %s",
                (scan_id,)
            )
            scan = cursor.fetchone()
            cursor.close()
            
            if scan:
                scan_dict = dict(scan)
                if scan_dict['image_paths'] is None:
                    scan_dict['image_paths'] = []
                return scan_dict
            return None
            
        except Exception as e:
            print(f"Error getting scan: {e}")
            return None

    def get_user_scans(self, user_id: str) -> List[Dict]:
        """Get all scans for a user"""
        try:
            if not self.connect():
                return []
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM scans WHERE user_id = %s ORDER BY created_at DESC",
                (user_id,)
            )
            scans = cursor.fetchall()
            cursor.close()
            
            result = []
            for scan in scans:
                scan_dict = dict(scan)
                if scan_dict['image_paths'] is None:
                    scan_dict['image_paths'] = []
                result.append(scan_dict)
            
            return result
            
        except Exception as e:
            print(f"Error getting user scans: {e}")
            return []

    def add_chat_message(self, scan_id: str, role: str, message: str) -> bool:
        """Add a message to chat history"""
        try:
            if not self.connect():
                return False
                
            cursor = self.connection.cursor()
            cursor.execute(
                "INSERT INTO chat_history (scan_id, role, message) VALUES (%s, %s, %s)",
                (scan_id, role, message)
            )
            cursor.close()
            return True
            
        except Exception as e:
            print(f"Error adding chat message: {e}")
            return False

    def get_chat_history(self, scan_id: str) -> List[Dict]:
        """Get chat history for a scan"""
        try:
            if not self.connect():
                return []
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM chat_history WHERE scan_id = %s ORDER BY created_at ASC",
                (scan_id,)
            )
            messages = cursor.fetchall()
            cursor.close()
            
            return [dict(msg) for msg in messages]
            
        except Exception as e:
            print(f"Error getting chat history: {e}")
            return []

    def delete_old_messages(self, days: int = 30):
        """Delete chat messages older than specified days"""
        try:
            if not self.connect():
                return 0
                
            cursor = self.connection.cursor()
            cursor.execute(
                "DELETE FROM chat_history WHERE created_at < NOW() - INTERVAL '%s days'",
                (days,)
            )
            deleted_count = cursor.rowcount
            cursor.close()
            
            print(f"Deleted {deleted_count} old chat messages")
            return deleted_count
            
        except Exception as e:
            print(f"Error deleting old messages: {e}")
            return 0

    def get_user_stats(self, user_id: str) -> Dict:
        """Get user statistics"""
        try:
            if not self.connect():
                return {}
                
            cursor = self.connection.cursor()
            
            # Get total scans
            cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = %s", (user_id,))
            total_scans = cursor.fetchone()[0]
            
            # Get average score
            cursor.execute(
                "SELECT AVG(score) FROM scans WHERE user_id = %s AND score IS NOT NULL", 
                (user_id,)
            )
            avg_score = cursor.fetchone()[0]
            
            # Get total messages
            cursor.execute(
                """SELECT COUNT(*) FROM chat_history ch 
                   JOIN scans s ON ch.scan_id = s.id 
                   WHERE s.user_id = %s AND ch.role = 'user'""", 
                (user_id,)
            )
            total_messages = cursor.fetchone()[0]
            
            cursor.close()
            
            return {
                'total_scans': total_scans,
                'average_score': float(avg_score) if avg_score else None,
                'total_messages': total_messages
            }
            
        except Exception as e:
            print(f"Error getting user stats: {e}")
            return {}

    # Legacy methods for backward compatibility (remove after migration)
    def create_password_reset_token(self, email: str, token: str, expires_at: datetime) -> bool:
        """Legacy method - use create_password_reset_code instead"""
        print("Warning: create_password_reset_token is deprecated, use create_password_reset_code")
        return self.create_password_reset_code(email, token, expires_at)

    def verify_password_reset_token(self, token: str) -> Optional[str]:
        """Legacy method - use verify_password_reset_code instead"""
        print("Warning: verify_password_reset_token is deprecated, use verify_password_reset_code")
        return self.verify_password_reset_code(token)

    def mark_token_as_used(self, token: str) -> bool:
        """Legacy method - use mark_code_as_used instead"""
        print("Warning: mark_token_as_used is deprecated, use mark_code_as_used")
        return self.mark_code_as_used(token)

    def cleanup_expired_tokens(self):
        """Legacy method - use cleanup_expired_codes instead"""
        print("Warning: cleanup_expired_tokens is deprecated, use cleanup_expired_codes")
        return self.cleanup_expired_codes()