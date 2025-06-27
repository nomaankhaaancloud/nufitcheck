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
            'password': os.getenv('DB_PASSWORD', '1234'),
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

            # Add MFA table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_mfa (
                    id SERIAL PRIMARY KEY,
                    user_email TEXT UNIQUE NOT NULL,
                    secret_key TEXT NOT NULL,
                    is_enabled BOOLEAN DEFAULT FALSE,
                    backup_codes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_email) REFERENCES auth_users (email) ON DELETE CASCADE
                )
            ''')

            
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

    def get_auth_user_by_email(self, email: str) -> Optional[Dict]:
        """Get authenticated user by email"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT id::text as id, email, created_at, is_active, updated_at FROM auth_users WHERE email = %s AND is_active = TRUE",
                (email.lower(),)
            )
            user = cursor.fetchone()
            cursor.close()
            
            if user:
                return {
                    'id': user['id'],  # Already converted to string in SQL
                    'email': user['email'],
                    'created_at': user['created_at'],
                    'is_active': user['is_active'],
                    'updated_at': user['updated_at']
                }
            return None
        except Exception as e:
            print(f"Error getting auth user: {e}")
            return None

    def authenticate_user(self, email: str, password: str) -> Optional[Dict]:
        """Authenticate user with email and password"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT id::text as id, email, password_hash, created_at, is_active FROM auth_users WHERE email = %s AND is_active = TRUE",
                (email.lower(),)
            )
            user = cursor.fetchone()
            cursor.close()
            
            if user and self.verify_password(password, user['password_hash']):
                return {
                    'id': user['id'],  # Already converted to string in SQL
                    'email': user['email'],
                    'created_at': user['created_at'],
                    'is_active': user['is_active']
                }
            return None
            
        except Exception as e:
            print(f"Error authenticating user: {e}")
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
        
    def create_mfa_secret(self, user_email: str, secret_key: str) -> bool:
        try:
            if not self.connect():
                return False

            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO user_mfa (user_email, secret_key, is_enabled)
                VALUES (%s, %s, FALSE)
                ON CONFLICT (user_email) DO UPDATE SET secret_key = EXCLUDED.secret_key
            ''', (user_email, secret_key))
            cursor.close()
            return True
        except Exception as e:
            print(f"Error creating MFA secret: {e}")
            return False

    def get_mfa_secret(self, user_email: str) -> str:
        try:
            if not self.connect():
                return None

            cursor = self.connection.cursor()
            cursor.execute('SELECT secret_key FROM user_mfa WHERE user_email = %s', (user_email,))
            result = cursor.fetchone()
            cursor.close()
            return result[0] if result else None
        except Exception as e:
            print(f"Error getting MFA secret: {e}")
            return None

    def enable_mfa(self, user_email: str) -> bool:
        try:
            if not self.connect():
                return False

            cursor = self.connection.cursor()
            cursor.execute('UPDATE user_mfa SET is_enabled = TRUE WHERE user_email = %s', (user_email,))
            updated = cursor.rowcount > 0
            cursor.close()
            return updated
        except Exception as e:
            print(f"Error enabling MFA: {e}")
            return False

    def disable_mfa(self, user_email: str) -> bool:
        try:
            if not self.connect():
                return False

            cursor = self.connection.cursor()
            cursor.execute('UPDATE user_mfa SET is_enabled = FALSE WHERE user_email = %s', (user_email,))
            updated = cursor.rowcount > 0
            cursor.close()
            return updated
        except Exception as e:
            print(f"Error disabling MFA: {e}")
            return False

    def is_mfa_enabled(self, user_email: str) -> bool:
        try:
            if not self.connect():
                return False

            cursor = self.connection.cursor()
            cursor.execute('SELECT is_enabled FROM user_mfa WHERE user_email = %s', (user_email,))
            result = cursor.fetchone()
            cursor.close()
            return bool(result[0]) if result else False
        except Exception as e:
            print(f"Error checking MFA status: {e}")
            return False

    def store_backup_codes(self, user_email: str, backup_codes: str) -> bool:
        try:
            if not self.connect():
                return False

            cursor = self.connection.cursor()
            cursor.execute('UPDATE user_mfa SET backup_codes = %s WHERE user_email = %s', (backup_codes, user_email))
            updated = cursor.rowcount > 0
            cursor.close()
            return updated
        except Exception as e:
            print(f"Error storing backup codes: {e}")
            return False

    def get_backup_codes(self, user_email: str) -> str:
        try:
            if not self.connect():
                return None

            cursor = self.connection.cursor()
            cursor.execute('SELECT backup_codes FROM user_mfa WHERE user_email = %s', (user_email,))
            result = cursor.fetchone()
            cursor.close()
            return result[0] if result else None
        except Exception as e:
            print(f"Error getting backup codes: {e}")
            return None

    def use_backup_code(self, user_email: str, code: str) -> bool:
        try:
            backup_codes = self.get_backup_codes(user_email)
            if not backup_codes:
                return False

            codes_list = backup_codes.split(',')
            if code in codes_list:
                codes_list.remove(code)
                new_codes = ','.join(codes_list)

                if not self.connect():
                    return False

                cursor = self.connection.cursor()
                cursor.execute('UPDATE user_mfa SET backup_codes = %s WHERE user_email = %s', (new_codes, user_email))
                updated = cursor.rowcount > 0
                cursor.close()
                return updated
            return False
        except Exception as e:
            print(f"Error using backup code: {e}")
            return False


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

    # Updated database.py methods

    def create_scan(self, scan_id: str, user_id: str, video_path: str, 
                image_paths: List[str], individual_scores: List[int], 
                feedback: str) -> bool:
        """Create a new scan with support for multiple user scores"""
        try:
            if not self.connect():
                print(f"Failed to connect to database for scan {scan_id}")
                return False
                
            cursor = self.connection.cursor()
            
            # Store individual scores as JSON array
            individual_scores_json = json.dumps(individual_scores) if individual_scores else None
            
            cursor.execute(
                """INSERT INTO scans (id, user_id, video_path, image_paths, 
                                    individual_scores, feedback) 
                VALUES (%s, %s, %s, %s, %s, %s)""",
                (scan_id, user_id, video_path, json.dumps(image_paths), 
                individual_scores_json, feedback)
            )
            cursor.close()
            print(f"Scan {scan_id} created successfully with {len(individual_scores) if individual_scores else 0} individual scores")
            return True
            
        except Exception as e:
            print(f"Error creating scan {scan_id}: {e}")
            return False

    # If you need to maintain backward compatibility, you can also add this method:
    def create_scan_legacy(self, scan_id: str, user_id: str, video_path: str, 
                        image_paths: List[str], score: Optional[int], feedback: str) -> bool:
        """Legacy method for backward compatibility - converts single score to list"""
        individual_scores = [score] if score is not None else []
        return self.create_scan(scan_id, user_id, video_path, image_paths, 
                            individual_scores, feedback)

    # Method to retrieve scan with multiple scores
    def get_scan_details(self, scan_id: str) -> Optional[dict]:
        """Get detailed scan information including all scores"""
        try:
            if not self.connect():
                return None
                
            cursor = self.connection.cursor()
            cursor.execute(
                """SELECT id, user_id, video_path, image_paths, individual_scores, 
                        feedback, created_at 
                FROM scans WHERE id = %s""",
                (scan_id,)
            )
            
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return {
                    "scan_id": result[0],
                    "user_id": result[1], 
                    "video_path": result[2],
                    "image_paths": json.loads(result[3]) if result[3] else [],
                    "individual_scores": json.loads(result[4]) if result[4] else [],
                    "feedback": result[5],
                    "created_at": result[6]
                }
            return None
            
        except Exception as e:
            print(f"Error getting scan details {scan_id}: {e}")
            return None

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
    def get_all_scans(self):
        """Get all scans from the database"""
        try:
            query = """
            SELECT id, user_id, video_path, image_paths, score, feedback, created_at 
            FROM scans 
            ORDER BY created_at DESC
            """
            self.cursor.execute(query)
            columns = [description[0] for description in self.cursor.description]
            results = self.cursor.fetchall()
            
            scans = []
            for row in results:
                scan_dict = dict(zip(columns, row))
                # Parse image_paths if it's stored as JSON string
                if scan_dict.get('image_paths'):
                    try:
                        scan_dict['image_paths'] = json.loads(scan_dict['image_paths'])
                    except:
                        scan_dict['image_paths'] = []
                scans.append(scan_dict)
            
            return scans
        except Exception as e:
            print(f"Error getting all scans: {e}")
            return []
    
    # Getting user profile using emial 
    def get_user_by_email(self, email):
        """Get user profile by email"""
        try:
            if not self.connect():
                return None

            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            return dict(user) if user else None

        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None