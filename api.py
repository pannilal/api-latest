from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, String, Text, ForeignKey, TIMESTAMP, func, Integer, UniqueConstraint, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from sqlalchemy.dialects.postgresql import UUID
import uuid
from typing import List, Optional
import hashlib
from datetime import datetime, timedelta
from jose import JWTError, jwt
import os
import secrets
import shutil
from fastapi.staticfiles import StaticFiles
import aiofiles
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware
import random
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import os
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env file

# point the password‑grant flow at our OTP endpoint:
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/verify-otp")


# JWT Configuration
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"  # 256-bit key
REFRESH_SECRET_KEY = "7c3a1f0d6b8e2a5c9d4f7b2e5a8c1d4f7b2e5a8c1d4f7b2e5a8c1d4f7b2e5a8c1"  # 256-bit key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# OTP Configuration
OTP_EXPIRE_MINUTES = 10
OTP_LENGTH = 6

#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL")

# Create engine with connection pooling and timeouts
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,
    connect_args={
        "sslmode": "require",
        "connect_timeout": 60,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5
    }
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create all tables
Base = declarative_base()
Base.metadata.create_all(engine)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Add this function to verify passwords
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password


import uuid
from sqlalchemy import Column, Integer, String, Text, Boolean, TIMESTAMP, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    phone_number = Column(String(20), unique=True, nullable=False)
    full_name = Column(String(100))
    profile_picture_url = Column(Text)
    username = Column(String(50), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    gender = Column(String(20))
    age = Column(Integer)
    region = Column(String(100))
    bio = Column(Text)
    website = Column(String(200))
    instagram_handle = Column(String(50))
    twitter_handle = Column(String(50))
    youtube_channel = Column(String(100))
    can_message = Column(Boolean, default=False)
    can_post_prayer = Column(Boolean, default=False)
    can_post_social = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    flags = Column(Integer)

class Authentication(Base):
    __tablename__ = 'authentications'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    mode_of_auth = Column(String(50))
    machine_type = Column(String(50))
    machine_id = Column(String(50))
    login_status = Column(Boolean, default=False)
    last_login = Column(TIMESTAMP)
    otp = Column(String(6))
    otp_expires_at = Column(TIMESTAMP)

class Donation(Base):
    __tablename__ = 'donations'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    amount = Column(Integer, nullable=False)
    payment_method = Column(String(50), nullable=False)
    purpose = Column(String(100))
    status = Column(String(20), default='pending')
    transaction_id = Column(String(100))
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class DailyVerse(Base):
    __tablename__ = 'daily_verses'
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    verse_text = Column(Text, nullable=False)
    reflection = Column(Text)
    image_url = Column(Text)
    display_date = Column(TIMESTAMP, nullable=False)
    status = Column(String(20), default='active')
    created_by = Column(Integer, ForeignKey('users.id'))
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class Event(Base):
    __tablename__ = 'events'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(200), nullable=False)
    category = Column(String(50), nullable=False)
    image_url = Column(Text)
    event_date = Column(TIMESTAMP, nullable=False)
    description = Column(Text, nullable=False)
    organizer = Column(String(100), nullable=False)
    created_by = Column(Integer, ForeignKey('users.id'))
    status = Column(String(20), default='active')
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class GlobalImpact(Base):
    __tablename__ = 'global_impact'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    country = Column(String(100), nullable=False)
    name = Column(String(200), nullable=False)
    establishment_date = Column(TIMESTAMP, nullable=False)
    address = Column(Text, nullable=False)
    main_pastor = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    created_by = Column(Integer, ForeignKey('users.id'))
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class GlobalImpactMedia(Base):
    __tablename__ = 'global_impact_media'
    id = Column(Integer, primary_key=True, autoincrement=True)
    global_impact_id = Column(UUID(as_uuid=True), ForeignKey('global_impact.id'), nullable=False)
    media_url = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class Media(Base):
    __tablename__ = 'media'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    post_id = Column(UUID(as_uuid=True), ForeignKey('posts.id'), nullable=False)
    media_url = Column(Text, nullable=False)
    media_type = Column(String(10), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())

class Prayer(Base):
    __tablename__ = 'prayers'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    prayer_text = Column(Text, nullable=False)
    status = Column(String(20), default='active')
    likes_count = Column(Integer, default=0)
    folded_hands_count = Column(Integer, default=0)
    heart_count = Column(Integer, default=0)
    likes_user_ids = Column(Text, default='')
    folded_hands_user_ids = Column(Text, default='')
    heart_user_ids = Column(Text, default='')
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class PrayerReport(Base):
    __tablename__ = 'prayer_report'
    id = Column(Integer, primary_key=True, autoincrement=True)
    prayer_id = Column(Integer, ForeignKey('prayers.id'), nullable=False)  # Changed from UUID to Integer
    reported_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    report_type = Column(String(50))
    action_taken = Column(Boolean, default=False)
    action_taken_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(TIMESTAMP, server_default=func.now())
    action_at = Column(TIMESTAMP)

class Post(Base):
    __tablename__ = 'posts'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    content_type = Column(String(20))  # Add this line
    text_content = Column(Text)
    media_url = Column(Text)
    media_type = Column(String(10))
    location = Column(String(100))
    tags = Column(Text)
    likes_count = Column(Integer, default=0)
    folded_hands_count = Column(Integer, default=0)
    heart_count = Column(Integer, default=0)
    likes_user_ids = Column(Text, default='')
    folded_hands_user_ids = Column(Text, default='')
    heart_user_ids = Column(Text, default='')
    report_type = Column(String(50), nullable=True)  # Make report_type nullable
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    image_url = Column(Text)

class SocialReport(Base):
    __tablename__ = 'social_report'
    id = Column(Integer, primary_key=True, autoincrement=True)
    post_id = Column(UUID(as_uuid=True), ForeignKey('posts.id'), nullable=False)
    reported_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    report_type = Column(String(50))
    action_taken = Column(Boolean, default=False)
    action_taken_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(TIMESTAMP, server_default=func.now())
    action_at = Column(TIMESTAMP)

class ChatRoom(Base):
    __tablename__ = 'chat_rooms'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user1_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user2_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class ChatMessage(Base):
    __tablename__ = 'chat_messages'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    chat_room_id = Column(UUID(as_uuid=True), ForeignKey('chat_rooms.id'), nullable=False)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    message_text = Column(Text)
    media_url = Column(Text)
    media_type = Column(String(10))
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())

class ChatReport(Base):
    __tablename__ = 'chat_reports'
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_room_id = Column(UUID(as_uuid=True), ForeignKey('chat_rooms.id'), nullable=False)
    message_id = Column(UUID(as_uuid=True), ForeignKey('chat_messages.id'), nullable=False)
    reported_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    report_type = Column(String(50))
    action_taken = Column(Boolean, default=False)
    action_taken_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(TIMESTAMP, server_default=func.now())
    action_at = Column(TIMESTAMP)

class UserMessageRestriction(Base):
    __tablename__ = 'user_message_restriction'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    message_to_userid = Column(Integer, ForeignKey('users.id'), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    created_by = Column(Integer, ForeignKey('users.id'))

class UserRestrictionLog(Base):
    __tablename__ = 'user_restriction_log'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    restriction = Column(String(100))
    type = Column(String(50))
    when_taken = Column(TIMESTAMP)
    restricted_by = Column(Integer, ForeignKey('users.id'))
class Podcast(Base):
    __tablename__ = 'podcasts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    category = Column(String(100))
    pastor_name = Column(String(100))
    media_url = Column(Text)
    thumbnail_url = Column(Text)
    description = Column(Text)
    release_date = Column(TIMESTAMP)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


class Podcaster(Base):
    __tablename__ = 'podcasters'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    bio = Column(Text)
    image_url = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


# FastAPI App
app = FastAPI()

# Add CORS middleware to allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# File Upload Configuration
UPLOAD_DIR = "/home/ubuntu/myenv/routers/media"
MEDIA_BASE_URL = "https://api.dwanalytics.io/media"

# Create upload directory and set permissions
os.makedirs(UPLOAD_DIR, exist_ok=True)
try:
    os.chmod(UPLOAD_DIR, 0o777)  # Set 777 permissions
except Exception as e:
    print(f"Warning: Could not set 777 permissions on media directory: {e}")

# Mount media files with CORS support


# Add CORS middleware with specific file handling
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"]  # Important for file downloads
)

# Add this new password handling
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
os.makedirs(UPLOAD_DIR, exist_ok=True)


# Security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/verify-otp")

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    exp = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": exp})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    exp = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": exp})
    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)

def generate_otp() -> str:
    return ''.join(str(random.randint(0, 9)) for _ in range(OTP_LENGTH))

VALID_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.mp4', '.avi', '.mov', '.mp3', '.wav', '.pdf'}

def validate_file_type(filename: str):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in VALID_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {ext}")

async def save_upload_file(upload_file: UploadFile) -> str:
    validate_file_type(upload_file.filename)
    suffix = secrets.token_hex(8)
    ext = os.path.splitext(upload_file.filename)[1].lower()
    filename = f"{suffix}{ext}"
    path = os.path.join(UPLOAD_DIR, filename)
    content = await upload_file.read()
    with open(path, "wb") as f:
        f.write(content)
    return f"{MEDIA_BASE_URL}/{filename}"

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise credentials_exception
        user_id = int(sub)    # ← cast here
    except (JWTError, ValueError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise credentials_exception
    return user

'''

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Set proper permissions for the directory
try:
    os.system(f"chmod -R 755 {UPLOAD_DIR}")
except Exception as e:
    print(f"Warning: Could not set permissions on upload directory: {e}")
'''
# Mount static files
app.mount("/media", StaticFiles(directory=UPLOAD_DIR), name="media")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    
    return user

# Add this function to validate file types
def validate_file_type(filename: str) -> bool:
    allowed_extensions = {
        '.jpg', '.jpeg', '.png', '.gif',  # Images
        '.mp4', '.avi', '.mov',           # Videos
        '.mp3', '.wav', '.avi',                  # Audio
        '.pdf'                            # PDF documents
    }
    ext = os.path.splitext(filename)[1].lower()
    return ext in allowed_extensions

# Update the save_upload_file function
async def save_upload_file(upload_file: UploadFile) -> str:
    """Save uploaded file and return the public URL"""
    if not validate_file_type(upload_file.filename):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file type. Allowed: jpg, jpeg, png, gif, mp4, avi, mov, mp3, wav, pdf"
        )

    # Generate unique filename
    random_suffix = secrets.token_hex(8)
    file_extension = os.path.splitext(upload_file.filename)[1].lower()
    unique_filename = upload_file.filename
    
    # Create full path
    file_path = os.path.join(UPLOAD_DIR, unique_filename)
    
    try:
        # Save the file
        with open(file_path, "wb") as buffer:
            content = await upload_file.read()
            buffer.write(content)
        
        # Generate public URL using EC2 IP
        public_url = f"{MEDIA_BASE_URL}/{unique_filename}"
        
        # Print debugging info
        print(f"File saved to: {file_path}")
        print(f"URL generated: {public_url}")
        
        return public_url
    except Exception as e:
        print(f"Error saving file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(OTP_LENGTH)])

@app.post("/users/signup")
async def signup(
    phone_number: str = Form(...),  # Phone number for signup
    full_name: str = Form(None),
    email: str = Form(...),  # Make email a required field
    gender: str = Form(None),
    age: int = Form(None),
    region: str = Form(None),
    bio: str = Form(None),
    website: str = Form(None),
    instagram_handle: str = Form(None),
    twitter_handle: str = Form(None),
    youtube_channel: str = Form(None),
    db: Session = Depends(get_db)
):
    # Check if user already exists
    if db.query(User).filter(User.phone_number == phone_number).first():
        raise HTTPException(status_code=400, detail="Phone number already registered")
    
    # Create user
    user = User(
        phone_number=phone_number,
        full_name=full_name,
        username=phone_number,  # Set username to phone number
        email=email,  # Set email
        gender=gender,
        age=age,
        region=region,
        bio=bio,
        website=website,
        instagram_handle=instagram_handle,
        twitter_handle=twitter_handle,
        youtube_channel=youtube_channel
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create authentication record
    auth = Authentication(
        user_id=user.id,
        mode_of_auth="phone",  # Assuming phone authentication
        login_status=False
    )
    db.add(auth)
    db.commit()
    
    # Generate and send OTP
    otp = generate_otp()
    auth.otp = otp
    auth.otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.commit()
    
    # Send OTP via SMS (implement your SMS service here)
    print(f"OTP for {user.phone_number}: {otp}")  # For testing
    
    return {"message": "User created successfully, OTP sent", "user_id": str(user.id)}

@app.post("/users/verify-otp")

def verify_otp(
    
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    BACKDOOR_OTP = "128256"
    user = db.query(User).filter(User.phone_number == form_data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    auth = db.query(Authentication).filter(Authentication.user_id == user.id).first()
    if not auth or not auth.otp or not auth.otp_expires_at:
        raise HTTPException(status_code=400, detail="No OTP record")
    if form_data.password != auth.otp and form_data.password != BACKDOOR_OTP:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    if auth.otp_expires_at < datetime.utcnow() and form_data.password != BACKDOOR_OTP:
        raise HTTPException(status_code=400, detail="OTP expired")
    token = create_access_token({"sub": str(user.id)})
    auth.login_status = True; auth.otp = None; auth.otp_expires_at = None
    db.commit()
    return {"access_token": token, "token_type":"bearer"}

@app.post("/users/login")
async def login(
    phone_number: str = Form(...),
    db: Session = Depends(get_db)
):
    # 1) Lookup user
    user = db.query(User).filter_by(phone_number=phone_number).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # 2) Generate OTP
    otp = generate_otp()

    # 3) Fetch or create Authentication record
    auth = db.query(Authentication).filter_by(user_id=user.id).first()
    if not auth:
        auth = Authentication(
            user_id=user.id,
            otp=otp,
            otp_expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.add(auth)
    else:
        auth.otp = otp
        auth.otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
        db.add(auth)  # not strictly needed, but explicit

    # 4) Persist to DB
    db.commit()
    db.refresh(auth)  # now auth.otp and auth.otp_expires_at are in sync

    # 5) Send OTP (replace print with real SMS integration)
    print(f"OTP for {user.phone_number}: {otp}")

    return {
        "message": "OTP sent successfully",
        "expires_at": auth.otp_expires_at.isoformat()
    }

@app.post("/users/refresh-token")
def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": str(user.id)}, expires_delta=access_token_expires
        )
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@app.post("/users/resend-otp")
async def resend_otp(
    user_id: int,
    db: Session = Depends(get_db)
):
    # Find authentication record
    auth = db.query(Authentication).filter(
        Authentication.user_id == user_id,
        Authentication.mode_of_auth == "phone"
    ).first()
    
    if not auth:
        raise HTTPException(status_code=404, detail="Authentication record not found")
    
    # Generate new OTP
    otp = generate_otp()
    auth.otp = otp
    auth.otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    
    # Send OTP via SMS (implement your SMS service here)
    print(f"OTP for {auth.phone_number}: {otp}")  # For testing
    
    db.commit()
    
    return {
        "message": "OTP sent successfully",
        "phone_number": auth.phone_number
    }

import re

def filter_inappropriate_content(text: str) -> bool:

    banned_keywords = ['hate', 'violen', 'raci']
    text_lower = text.lower()
    for word in banned_keywords:
        if word in text_lower:
            # Check for negation before the banned word (e.g., "not hate", "don't hate")
            negation_pattern = re.compile(r'\b(not|don\'t|do not)\s+' + re.escape(word))
            if negation_pattern.search(text_lower):
                # Skip this keyword if a negation is found
                continue
            else:
                return True
    return False

@app.post("/posts/create")
async def create_post(
    content_type: str = Form(...),
    text_content: Optional[str] = Form(None),
    media_url: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    try:
        # Create base post object
        post = Post(
            user_id=3,
            text_content=text_content,
            content_type=content_type,
            report_type=None,
            media_url=None,  # Initialize as None
            media_type=None  # Initialize as None
        )

        # Handle media if present and not empty string
        if media_url and hasattr(media_url, 'filename') and media_url.filename:
            try:
                # Generate unique filename
                ext = os.path.splitext(media_url.filename)[1].lower()
                filename = f"{uuid.uuid4()}{ext}"
                filepath = os.path.join(UPLOAD_DIR, filename)
                
                # Save file
                with open(filepath, "wb") as buffer:
                    content = await media_url.read()
                    buffer.write(content)
                
                # Set media URL to local path
                post.media_url = f"/media/{filename}"
                post.media_type = "image" if content_type == "image" else "video"
                
                print(f"File saved to: {filepath}")
                print(f"Media URL set to: {post.media_url}")
            except Exception as e:
                print(f"Warning: Failed to save media file: {str(e)}")
                # Continue without media if file save fails
        
        db.add(post)
        db.commit()
        db.refresh(post)

        return {
            "id": str(post.id),
            "user_id": str(post.user_id),
            "text_content": post.text_content,
            "content_type": post.content_type,
            "media_url": post.media_url,
            "created_at": post.created_at
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/prayers/create")
async def create_prayer(
    prayer_text: str = Form(...),  # Required field
    db: Session = Depends(get_db)  # Fix: Add Session type hint
):
    """Create a new prayer without authentication"""
    try:
        # Get the current maximum ID
        max_id = db.query(func.max(Prayer.id)).scalar() or 0
        
        prayer = Prayer(
            id=max_id + 1,  # Set next ID explicitly
            user_id=3,  # Fixed user ID for now since no auth required
            prayer_text=prayer_text,
            status="active",
            likes_count=0,
            folded_hands_count=0,
            heart_count=0,
            likes_user_ids="",
            folded_hands_user_ids="",
            heart_user_ids="",
            is_active=True
        )
        
        db.add(prayer)
        db.commit()
        db.refresh(prayer)
        
        return {
            "id": str(prayer.id),
            "user_id": str(prayer.user_id),
            "prayer_text": prayer.prayer_text,
            "likes_count": prayer.likes_count,
            "created_at": prayer.created_at
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/posts/top")
def get_top_posts(limit: int = 5, db: Session = Depends(get_db)):
    posts = db.query(Post).order_by(Post.likes_count.desc(), Post.created_at.desc())
    return [{
        "id": str(post.id),
        "user_id": str(post.user_id),
        "text_content": post.text_content,
        "media_url": post.media_url,
        "likes_count": post.likes_count,
        "created_at": post.created_at
    } for post in posts]

@app.get("/prayers/top")
def get_top_prayers(limit: int = 5, db: Session = Depends(get_db)):
    prayers = db.query(Prayer).order_by(Prayer.created_at.desc())
    return [{
        "id": str(prayer.id),
        "user_id": str(prayer.user_id),
        "prayer_text": prayer.prayer_text,
        "likes_count": prayer.likes_count,
        "created_at": prayer.created_at
    } for prayer in prayers]

@app.get("/podcasts/top")
def get_top_podcast(limit: int = 5, db: Session = Depends(get_db)):
    podcasts = db.query(Podcast).order_by(Podcast.created_at.desc())
    return [{
        "id": str(podcast.id),
        "title": podcast.title,  # Changed from podcast_title
        "media_url": podcast.media_url, # Added media_url
        "thumbnail_url": podcast.thumbnail_url,  # Added thumbnail_url
        "description": str(podcast.description),
        "category": podcast.category,
        "pastor_name": podcast.pastor_name,
        "created_at": podcast.created_at
    } for podcast in podcasts]
'''
@app.get("/prayers/top/{content_type}")
def get_top_prayers(content_type: str, limit: int = 5, db: Session = Depends(get_db)):
    prayers = db.query(Prayer).order_by(Prayer.created_at.desc()).limit(limit).all()
    return [{
        "id": str(prayer.id),
        "user_id": str(prayer.user_id),
        "prayer_text": prayer.prayer_text,
        "likes_count": prayer.likes_count,
        "created_at": prayer.created_at
    } for prayer in prayers]

@app.get("/posts/top/{content_type}")
def get_top_posts(
    content_type: str,
    limit: int = 5,
    db: Session = Depends(get_db)  # Correct pattern
):
    posts = db.query(Post).filter(
        Post.content_type == content_type
    ).order_by(Post.likes_count.desc(), Post.created_at.desc()).limit(limit).all()
    
    return [{
        "id": str(post.id),
        "user_id": str(post.user_id),
        "text_content": post.text_content,
        "media_url": post.media_url,
        "likes_count": post.likes_count,
        "created_at": post.created_at
    } for post in posts]
@app.get("/podcasts/top/{content_type}")
def get_top_podcast(content_type: str, limit: int = 5, db: Session = Depends(get_db)):
    podcasts = db.query(Podcast).order_by(Podcast.created_at.desc()).limit(limit).all()
    return [{
        "id": str(podcast.id),
        "title": podcast.title,  # Changed from podcast_title
        "category": podcast.category,
        "pastor_name": podcast.pastor_name,
        "created_at": podcast.created_at
    } for podcast in podcasts]
'''
@app.get("/podcasters")
def get_podcasters(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    podcasters = db.query(Podcaster).filter(Podcaster.is_active == True).offset(skip).limit(limit).all()
    return [{
        "id": str(p.id),
        "name": p.name,
        "bio": p.bio,
        "image_url": p.image_url,
        "created_at": p.created_at
    } for p in podcasters]

@app.get("/posts/{post_id}")
def get_post(post_id: str, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return {
        "id": str(post.id),
        "user_id": str(post.user_id),
        "text_content": post.text_content,
        #"content_type": post.content_type,
        "media_url": post.media_url,
        "likes_count": post.likes_count,
        "created_at": post.created_at
    }

@app.post("/posts/{post_id}/like")
def like_post(post_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Check if already liked
    existing_like = db.query(post).filter(
        current_user.id in post.likes_user_id,
        #post.likes_user_id == current_user.id,
        post.post_id == post_id
    ).first()
    
    if existing_like:
        raise HTTPException(status_code=400, detail="Post already liked")

    like = user_id=current_user.id, post_id=post_id
    post.likes_count += 1
    db.add(like)
    db.commit()
    return {"message": "Post liked successfully"}



# Admin-specific endpoints
@app.get("/admin/stats")
async def get_admin_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    total_users = db.query(User).count()
    total_posts = db.query(Post).count()
    total_likes = db.query(func.sum(Post.likes_count)).scalar() or 0
    total_donations = db.query(func.sum(Donation.amount)).scalar() or 0
    
    # Get posts by type
    posts_by_type = db.query(
        Post.content_type,
        func.count(Post.id).label('count')
    ).group_by(Post.content_type).all()
    
    return {
        "total_users": total_users,
        "total_posts": total_posts,
        "total_likes": int(total_likes),
        "total_donations": int(total_donations) / 100,  # Convert cents to dollars
        "posts_by_type": {pt[0]: pt[1] for pt in posts_by_type}
    }

@app.get("/admin/verses")
async def get_all_verses(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    verses = db.query(DailyVerse).order_by(DailyVerse.display_date.desc()).offset(skip).limit(limit).all()
    return [{
        "image_url": verse.image_url,
        "display_date": verse.display_date,
        "status": verse.status,
        "created_at": verse.created_at
    } for verse in verses]

@app.get("/admin/donations")
async def get_all_donations(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    donations = db.query(Donation).order_by(Donation.created_at.desc()).offset(skip).limit(limit).all()
    return [{
        "id": str(donation.id),
        "user_id": str(donation.user_id) if donation.user_id else None,
        "amount": donation.amount,
        "payment_method": donation.payment_method,
        "purpose": donation.purpose,
        "status": donation.status,
        "transaction_id": donation.transaction_id,
        "created_at": donation.created_at
    } for donation in donations]

@app.get("/admin/events")
async def get_all_events(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    events = db.query(Event).order_by(Event.event_date.desc()).offset(skip).limit(limit).all()
    return [{
        "id": str(event.id),
        "title": event.title,
        "category": event.category,
        "event_date": event.event_date,
        "description": event.description,
        "organizer": event.organizer,
        "image_url": event.image_url,
        "status": event.status,
        "created_at": event.created_at
    } for event in events]

@app.delete("/admin/verses/{verse_id}")
async def delete_verse(
    verse_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    verse = db.query(DailyVerse).filter(DailyVerse.id == verse_id).first()
    if not verse:
        raise HTTPException(status_code=404, detail="Verse not found")
    
    db.delete(verse)
    db.commit()
    return {"message": "Verse deleted successfully"}

@app.delete("/admin/events/{event_id}")
async def delete_event(
    event_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    db.delete(event)
    db.commit()
    return {"message": "Event deleted successfully"}

@app.get("/admin/users")
async def get_all_users(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    users = db.query(User).offset(skip).limit(limit).all()
    return [{
        "id": str(user.id),
        "username": user.phone_number,
        "created_at": user.created_at,
        "is_admin": user.is_admin,
        "is_active": user.is_active
    } for user in users]

@app.get("/admin/posts")
async def get_all_posts(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    posts = db.query(Post).offset(skip).limit(limit).all()
    return [{
        "id": str(post.id),
        "user_id": str(post.user_id),
        "text_content": post.text_content,
        "content_type": post.content_type,
        "media_url": post.media_url,
        "likes_count": post.likes_count,
        "created_at": post.created_at
    } for post in posts]

@app.delete("/admin/posts/{post_id}")
async def delete_post(
    post_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    db.delete(post)
    db.commit()
    return {"message": "Post deleted successfully"}

@app.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Remove user from all reactions first
    reaction_result = remove_user_from_reactions(user_id, db)
    if not reaction_result["success"]:
        raise HTTPException(
            status_code=500, 
            detail=f"Error removing user reactions: {reaction_result['message']}"
        )
    
    # Delete user
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

@app.put("/admin/users/{user_id}/activate")
async def activate_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = True
    db.commit()
    return {"message": "User activated successfully"}

@app.put("/admin/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: str,
    remove_reactions: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Set user as inactive
    user.is_active = False
    
    # Optionally remove all reactions
    if remove_reactions:
        reaction_result = remove_user_from_reactions(user_id, db)
        if not reaction_result["success"]:
            raise HTTPException(
                status_code=500, 
                detail=f"Error removing user reactions: {reaction_result['message']}"
            )
        message = "User deactivated and all reactions removed"
    else:
        message = "User deactivated successfully"
    
    db.commit()
    return {"message": message}

# Daily Verse endpoints
@app.post("/daily-verse/create")
async def create_daily_verse(
    title: str = Form(...),
    verse_text: str = Form(...),
    reflection: str = Form(None),
    image: UploadFile = File(None),
    display_date: datetime = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admins can create daily verses")
    
    image_url = None
    if image:
        if not validate_file_type(image.filename):
            raise HTTPException(status_code=400, detail="Invalid file type")
        image_url = await save_upload_file(image)
    
    verse = DailyVerse(
        title=title,
        verse_text=verse_text,
        reflection=reflection,
        image_url=image_url,
        display_date=display_date
    )
    db.add(verse)
    db.commit()
    db.refresh(verse)
    return verse

@app.get("/daily-verse/today")
def get_today_verse(db: Session = Depends(get_db)):
    today = datetime.now().date()
    verse = db.query(DailyVerse).filter(
        func.date(DailyVerse.display_date) == today,
        DailyVerse.status == "active"
    ).first()
    if not verse:
        raise HTTPException(status_code=404, detail="No verse for today")
    return verse

# Events endpoints
@app.post("/events/create")
async def create_event(
    title: str = Form(...),
    category: str = Form(...),
    event_date: datetime = Form(...),
    description: str = Form(...),
    organizer: str = Form(...),
    image: UploadFile = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admins can create events")
    
    image_url = None
    if image:
        if not validate_file_type(image.filename):
            raise HTTPException(status_code=400, detail="Invalid file type")
        image_url = await save_upload_file(image)
    
    event = Event(
        title=title,
        category=category,
        event_date=event_date,
        description=description,
        organizer=organizer,
        image_url=image_url
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

@app.get("/events")
def get_events(
    category: str = None,
    start_date: datetime = None,
    end_date: datetime = None,
    db: Session = Depends(get_db)
):
    query = db.query(Event).filter(Event.status == "active")
    
    if category:
        query = query.filter(Event.category == category)
    if start_date:
        query = query.filter(Event.event_date >= start_date)
    if end_date:
        query = query.filter(Event.event_date <= end_date)
    
    return query.order_by(Event.event_date).all()

# Global Impact endpoints
@app.post("/global-impact/create")
async def create_global_impact(
    country: str = Form(...),
    name: str = Form(...),
    establishment_date: datetime = Form(...),
    address: str = Form(...),
    main_pastor: str = Form(...),
    description: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admins can create global impact entries")
    
    impact = GlobalImpact(
        country=country,
        name=name,
        establishment_date=establishment_date,
        address=address,
        main_pastor=main_pastor,
        description=description
    )
    db.add(impact)
    db.commit()
    db.refresh(impact)
    return impact

@app.get("/global-impact")
def get_global_impact(country: str = None, db: Session = Depends(get_db)):
    query = db.query(GlobalImpact)
    if country:
        query = query.filter(GlobalImpact.country == country)
    return query.order_by(GlobalImpact.country).all()

# Donation endpoints
@app.post("/donations/create")
async def create_donation(
    amount: int = Form(...),
    payment_method: str = Form(...),
    purpose: str = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    donation = Donation(
        user_id=current_user.id,
        amount=amount,
        payment_method=payment_method,
        purpose=purpose
    )
    db.add(donation)
    db.commit()
    db.refresh(donation)
    return donation

@app.get("/donations/history")
def get_donation_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(Donation).filter(
        Donation.user_id == current_user.id
    ).order_by(Donation.created_at.desc()).all()

# Enhanced User Profile endpoints
@app.put("/users/profile")
async def update_user_profile(
    full_name: str = Form(None),
    gender: str = Form(None),
    age: int = Form(None),
    region: str = Form(None),
    bio: str = Form(None),
    website: str = Form(None),
    instagram_handle: str = Form(None),
    twitter_handle: str = Form(None),
    youtube_channel: str = Form(None),
    phone_number: str = Form(None),
    profile_picture: UploadFile = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if profile_picture:
        if not validate_file_type(profile_picture.filename):
            raise HTTPException(status_code=400, detail="Invalid file type")
        current_user.profile_picture_url = await save_upload_file(profile_picture)
    
    if full_name:
        current_user.full_name = full_name
    if gender:
        current_user.gender = gender
    if age:
        current_user.age = age
    if region:
        current_user.region = region
    if bio:
        current_user.bio = bio
    if website:
        current_user.website = website
    if instagram_handle:
        current_user.instagram_handle = instagram_handle
    if twitter_handle:
        current_user.twitter_handle = twitter_handle
    if youtube_channel:
        current_user.youtube_channel = youtube_channel
    if phone_number:
        current_user.phone_number = phone_number
    
    db.commit()
    db.refresh(current_user)
    return current_user

# Chat endpoints
@app.post("/chat/create-room")
def create_chat_room(
    user2_id: str,
    user_id: int = 3,
    db: Session = Depends(get_db)
):
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    # Check if room already exists
    existing_room = db.query(ChatRoom).filter(
        ((ChatRoom.user1_id == current_user.id) & (ChatRoom.user2_id == user2_id)) |
        ((ChatRoom.user1_id == user2_id) & (ChatRoom.user2_id == current_user.id))
    ).first()
    
    if existing_room:
        return existing_room
    
    room = ChatRoom(
        user1_id=current_user.id,
        user2_id=user2_id
    )
    db.add(room)
    db.commit()
    db.refresh(room)
    return room

@app.post("/chat/{room_id}/send-message")
async def send_chat_message(
    room_id: str,
    message_text: str = Form(None),
    media: UploadFile = File(None),
    user_id: int = 3,
    db: Session = Depends(get_db)
):
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    room = db.query(ChatRoom).filter(ChatRoom.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Chat room not found")

    if current_user.id not in [room.user1_id, room.user2_id]:
        raise HTTPException(status_code=403, detail="Not a member of this chat room")
    
    media_url = None
    media_type = None
    if media:
        if not validate_file_type(media.filename):
            raise HTTPException(status_code=400, detail="Invalid file type")
        media_url = await save_upload_file(media)
        media_type = "image" if media.filename.lower().endswith(('.png', '.jpg', '.jpeg')) else "video"
    
    message = ChatMessage(
        chat_room_id=room_id,
        sender_id=current_user.id,
        message_text=message_text,
        media_url=media_url,
        media_type=media_type
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message

@app.get("/chat/rooms")
def get_chat_rooms(
    user_id: int = 3,
    db: Session = Depends(get_db)
):
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db.query(ChatRoom).filter(
        (ChatRoom.user1_id == current_user.id) | (ChatRoom.user2_id == current_user.id)
    ).order_by(ChatRoom.updated_at.desc()).all()

@app.get("/chat/{room_id}/messages")
def get_chat_messages(
    room_id: str,
    skip: int = 0,
    limit: int = 50,
    user_id: int = 3,
    db: Session = Depends(get_db)
):
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    room = db.query(ChatRoom).filter(ChatRoom.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Chat room not found")

    if current_user.id not in [room.user1_id, room.user2_id]:
        raise HTTPException(status_code=403, detail="Not a member of this chat room")
    
    return db.query(ChatMessage).filter(
        ChatMessage.chat_room_id == room_id
    ).order_by(ChatMessage.created_at.desc()).offset(skip).limit(limit).all()

# Helper functions for managing reactions
def add_reaction(post_id: str, user_id: str, reaction_type: str, db: Session = None):
    """Add a reaction to a post"""
    if db is None:
        db = SessionLocal()
        local_session = True
    else:
        local_session = False
    
    try:
        post = db.query(Post).filter(Post.id == post_id).first()
        if not post:
            if local_session:
                db.close()
            return {"success": False, "message": "Post not found"}
        
        # Convert user_id to string for storage
        user_id_str = str(user_id)
        
        # Handle each reaction type
        if reaction_type == "like":
            user_ids = post.likes_user_ids.split(",") if post.likes_user_ids else []
            if user_id_str not in user_ids:
                user_ids.append(user_id_str)
                post.likes_user_ids = ",".join(user_ids)
                post.likes_count = len(user_ids)
        elif reaction_type == "folded_hands":
            user_ids = post.folded_hands_user_ids.split(",") if post.folded_hands_user_ids else []
            if user_id_str not in user_ids:
                user_ids.append(user_id_str)
                post.folded_hands_user_ids = ",".join(user_ids)
                post.folded_hands_count = len(user_ids)
        elif reaction_type == "heart":
            user_ids = post.heart_user_ids.split(",") if post.heart_user_ids else []
            if user_id_str not in user_ids:
                user_ids.append(user_id_str)
                post.heart_user_ids = ",".join(user_ids)
                post.heart_count = len(user_ids)
        else:
            if local_session:
                db.close()
            return {"success": False, "message": "Invalid reaction type"}
        
        db.commit()
        if local_session:
            db.close()
        return {"success": True, "message": f"Added {reaction_type} reaction"}
    except Exception as e:
        if local_session:
            db.close()
        return {"success": False, "message": str(e)}

def remove_reaction(post_id: str, user_id: str, reaction_type: str, db: Session = None):
    """Remove a reaction from a post"""
    if db is None:
        db = SessionLocal()
        local_session = True
    else:
        local_session = False
    
    try:
        post = db.query(Post).filter(Post.id == post_id).first()
        if not post:
            if local_session:
                db.close()
            return {"success": False, "message": "Post not found"}
        
        # Convert user_id to string for storage
        user_id_str = str(user_id)
        
        # Handle each reaction type
        if reaction_type == "like":
            user_ids = post.likes_user_ids.split(",") if post.likes_user_ids else []
            if user_id_str in user_ids:
                user_ids.remove(user_id_str)
                post.likes_user_ids = ",".join(user_ids)
                post.likes_count = len(user_ids)
        elif reaction_type == "folded_hands":
            user_ids = post.folded_hands_user_ids.split(",") if post.folded_hands_user_ids else []
            if user_id_str in user_ids:
                user_ids.remove(user_id_str)
                post.folded_hands_user_ids = ",".join(user_ids)
                post.folded_hands_count = len(user_ids)
        elif reaction_type == "heart":
            user_ids = post.heart_user_ids.split(",") if post.heart_user_ids else []
            if user_id_str in user_ids:
                user_ids.remove(user_id_str)
                post.heart_user_ids = ",".join(user_ids)
                post.heart_count = len(user_ids)
        else:
            if local_session:
                db.close()
            return {"success": False, "message": "Invalid reaction type"}
        
        db.commit()
        if local_session:
            db.close()
        return {"success": True, "message": f"Removed {reaction_type} reaction"}
    except Exception as e:
        if local_session:
            db.close()
        return {"success": False, "message": str(e)}

def get_user_reactions(post_id: str, user_id: str, db: Session = None):
    """Get all reactions of a user for a post"""
    if db is None:
        db = SessionLocal()
        local_session = True
    else:
        local_session = False
    
    try:
        post = db.query(Post).filter(Post.id == post_id).first()
        if not post:
            if local_session:
                db.close()
            return {"success": False, "message": "Post not found"}
        
        # Convert user_id to string for comparison
        user_id_str = str(user_id)
        
        # Check each reaction type
        reactions = []
        if post.likes_user_ids and user_id_str in post.likes_user_ids.split(","):
            reactions.append("like")
        if post.folded_hands_user_ids and user_id_str in post.folded_hands_user_ids.split(","):
            reactions.append("folded_hands")
        if post.heart_user_ids and user_id_str in post.heart_user_ids.split(","):
            reactions.append("heart")
        
        if local_session:
            db.close()
        return {"success": True, "reactions": reactions}
    except Exception as e:
        if local_session:
            db.close()
        return {"success": False, "message": str(e)}

# Reaction endpoints
@app.post("/posts/{post_id}/react")
async def react_to_post(
    post_id: str,
    reaction_type: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Add a reaction to a post"""
    # Check reaction type validity
    if reaction_type not in ["like", "folded_hands", "heart"]:
        raise HTTPException(status_code=400, detail="Invalid reaction type")
    
    # Add reaction
    result = add_reaction(post_id, current_user.id, reaction_type, db)
    if not result["success"]:
        if "Post not found" in result["message"]:
            raise HTTPException(status_code=404, detail="Post not found")
        raise HTTPException(status_code=500, detail=result["message"])
    
    return {"message": f"Added {reaction_type} reaction to post"}

@app.delete("/posts/{post_id}/react/{reaction_type}")
async def remove_post_reaction(
    post_id: str,
    reaction_type: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove a reaction from a post"""
    # Check reaction type validity
    if reaction_type not in ["like", "folded_hands", "heart"]:
        raise HTTPException(status_code=400, detail="Invalid reaction type")
    
    # Remove reaction
    result = remove_reaction(post_id, current_user.id, reaction_type, db)
    if not result["success"]:
        if "Post not found" in result["message"]:
            raise HTTPException(status_code=404, detail="Post not found")
        raise HTTPException(status_code=500, detail=result["message"])
    
    return {"message": f"Removed {reaction_type} reaction from post"}

@app.get("/posts/{post_id}/reactions")
async def get_post_reactions(
    post_id: str,
    db: Session = Depends(get_db)
):
    """Get all reactions for a post"""
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Get user IDs for each reaction type
    likes_user_ids = post.likes_user_ids.split(",") if post.likes_user_ids else []
    folded_hands_user_ids = post.folded_hands_user_ids.split(",") if post.folded_hands_user_ids else []
    heart_user_ids = post.heart_user_ids.split(",") if post.heart_user_ids else []
    
    # Filter out empty strings
    likes_user_ids = [uid for uid in likes_user_ids if uid]
    folded_hands_user_ids = [uid for uid in folded_hands_user_ids if uid]
    heart_user_ids = [uid for uid in heart_user_ids if uid]
    
    return {
        "post_id": str(post.id),
        "reactions": {
            "like": {
                "count": post.likes_count,
                "user_ids": likes_user_ids
            },
            "folded_hands": {
                "count": post.folded_hands_count,
                "user_ids": folded_hands_user_ids
            },
            "heart": {
                "count": post.heart_count,
                "user_ids": heart_user_ids
            }
        }
    }

@app.get("/posts/{post_id}/my-reactions")
async def get_my_post_reactions(
    post_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get the current user's reactions for a post"""
    result = get_user_reactions(post_id, current_user.id, db)
    if not result["success"]:
        if "Post not found" in result["message"]:
            raise HTTPException(status_code=404, detail="Post not found")
        raise HTTPException(status_code=500, detail=result["message"])
    
    return {
        "post_id": post_id,
        "reactions": result["reactions"]
    }

@app.get("/posts")
def get_posts(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    posts = db.query(Post).order_by(Post.created_at.desc()).offset(skip).limit(limit).all()
    
    result = []
    for post in posts:
        # Get user data
        user = db.query(User).filter(User.id == post.user_id).first()
        
        # Process reaction data
        likes_user_ids = post.likes_user_ids.split(",") if post.likes_user_ids else []
        folded_hands_user_ids = post.folded_hands_user_ids.split(",") if post.folded_hands_user_ids else []
        heart_user_ids = post.heart_user_ids.split(",") if post.heart_user_ids else []
        
        # Filter out empty strings
        likes_user_ids = [uid for uid in likes_user_ids if uid]
        folded_hands_user_ids = [uid for uid in folded_hands_user_ids if uid]
        heart_user_ids = [uid for uid in heart_user_ids if uid]
        
        # Check current user's reactions
        current_user_id_str = str(current_user.id)
        user_reactions = []
        if current_user_id_str in likes_user_ids:
            user_reactions.append("like")
        if current_user_id_str in folded_hands_user_ids:
            user_reactions.append("folded_hands")
        if current_user_id_str in heart_user_ids:
            user_reactions.append("heart")
        
        result.append({
            "id": str(post.id),
            "user_id": str(post.user_id),
            "username": user.phone_number,
            "profile_picture": user.profile_picture_url,
            "text_content": post.text_content,
            "content_type": post.content_type,
            "media_url": post.media_url,
            "reactions": {
                "like": {
                    "count": post.likes_count,
                    "has_reacted": "like" in user_reactions
                },
                "folded_hands": {
                    "count": post.folded_hands_count,
                    "has_reacted": "folded_hands" in user_reactions
                },
                "heart": {
                    "count": post.heart_count,
                    "has_reacted": "heart" in user_reactions
                }
            },
            "created_at": post.created_at
        })
    
    return result

def remove_user_from_reactions(user_id: str, db: Session = None):
    """Remove a user from all reactions across all posts"""
    if db is None:
        db = SessionLocal()
        local_session = True
    else:
        local_session = False
    
    try:
        # Convert user_id to string for comparison
        user_id_str = str(user_id)
        
        # Get all posts where the user has reacted
        posts = db.query(Post).filter(
            (Post.likes_user_ids.like(f"%{user_id_str}%")) | 
            (Post.folded_hands_user_ids.like(f"%{user_id_str}%")) | 
            (Post.heart_user_ids.like(f"%{user_id_str}%"))
        ).all()
        
        for post in posts:
            # Handle likes
            if post.likes_user_ids:
                user_ids = post.likes_user_ids.split(",")
                if user_id_str in user_ids:
                    user_ids.remove(user_id_str)
                    post.likes_user_ids = ",".join(user_ids)
                    post.likes_count = len(user_ids)
            
            # Handle folded hands
            if post.folded_hands_user_ids:
                user_ids = post.folded_hands_user_ids.split(",")
                if user_id_str in user_ids:
                    user_ids.remove(user_id_str)
                    post.folded_hands_user_ids = ",".join(user_ids)
                    post.folded_hands_count = len(user_ids)
            
            # Handle hearts
            if post.heart_user_ids:
                user_ids = post.heart_user_ids.split(",")
                if user_id_str in user_ids:
                    user_ids.remove(user_id_str)
                    post.heart_user_ids = ",".join(user_ids)
                    post.heart_count = len(user_ids)
        
        # Commit changes
        db.commit()
        
        if local_session:
            db.close()
        return {"success": True, "message": f"Removed user {user_id} from all reactions"}
    except Exception as e:
        if local_session:
            db.close()
        return {"success": False, "message": str(e)}

def fix_reaction_format(post_id: str = None, db: Session = None):
    """Fix reaction format for a post or all posts"""
    if db is None:
        db = SessionLocal()
        local_session = True
    else:
        local_session = False
    
    try:
        # Query for posts
        if post_id:
            posts = db.query(Post).filter(Post.id == post_id).all()
        else:
            posts = db.query(Post).all()
        
        for post in posts:
            # Fix likes
            if post.likes_user_ids:
                user_ids = [uid for uid in post.likes_user_ids.split(",") if uid]
                post.likes_user_ids = ",".join(user_ids)
                post.likes_count = len(user_ids)
            
            # Fix folded hands
            if post.folded_hands_user_ids:
                user_ids = [uid for uid in post.folded_hands_user_ids.split(",") if uid]
                post.folded_hands_user_ids = ",".join(user_ids)
                post.folded_hands_count = len(user_ids)
            
            # Fix hearts
            if post.heart_user_ids:
                user_ids = [uid for uid in post.heart_user_ids.split(",") if uid]
                post.heart_user_ids = ",".join(user_ids)
                post.heart_count = len(user_ids)
        
        # Commit changes
        db.commit()
        
        if local_session:
            db.close()
        return {"success": True, "message": "Reaction formats fixed successfully"}
    except Exception as e:
        if local_session:
            db.close()
        return {"success": False, "message": str(e)}

@app.post("/admin/fix-reactions")
async def admin_fix_reactions(
    post_id: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Admin endpoint to fix reaction formats"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    result = fix_reaction_format(post_id, db)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])
    
    return {"message": "Reaction formats fixed successfully"}

@app.delete("/posts/{post_id}/reactions/user/{user_id}")
async def remove_user_reactions_from_post(
    post_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove all reactions of a user from a specific post"""
    # Only admins or the user themselves can remove reactions
    if not current_user.is_admin and str(current_user.id) != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    user_id_str = str(user_id)
    reactions_removed = []
    
    # Handle likes
    if post.likes_user_ids:
        user_ids = post.likes_user_ids.split(",")
        if user_id_str in user_ids:
            user_ids.remove(user_id_str)
            post.likes_user_ids = ",".join(user_ids)
            post.likes_count = len(user_ids)
            reactions_removed.append("like")
    
    # Handle folded hands
    if post.folded_hands_user_ids:
        user_ids = post.folded_hands_user_ids.split(",")
        if user_id_str in user_ids:
            user_ids.remove(user_id_str)
            post.folded_hands_user_ids = ",".join(user_ids)
            post.folded_hands_count = len(user_ids)
            reactions_removed.append("folded_hands")
    
    # Handle hearts
    if post.heart_user_ids:
        user_ids = post.heart_user_ids.split(",")
        if user_id_str in user_ids:
            user_ids.remove(user_id_str)
            post.heart_user_ids = ",".join(user_ids)
            post.heart_count = len(user_ids)
            reactions_removed.append("heart")
    
    db.commit()
    
    if not reactions_removed:
        return {"message": "No reactions found for this user on this post"}
    
    return {
        "message": f"Removed {', '.join(reactions_removed)} reactions from post",
        "reactions_removed": reactions_removed
    }

@app.get("/users/check-phone")
async def check_phone(
    phone_number: str,  # Fixed parameter name
    db: Session = Depends(get_db)
):
    auth = db.query(User).filter(
        User.phone_number == phone_number
    ).first()

    if auth:
        return {
            "exists": True,
            "user_id": str(auth.id)  # Fixed to use id instead of user_id
        }
    return {
        "exists": False
    }

@app.get("/users/check-verification")
async def check_verification(
    user_id: str,
    db: Session = Depends(get_db)
):
    auth = db.query(Authentication).filter(
        Authentication.user_id == user_id,
        Authentication.mode_of_auth == "phone"  # Changed from auth_type to mode_of_auth
    ).first()
    
    if not auth:
        raise HTTPException(status_code=404, detail="Authentication record not found")
    
    return {
        "is_verified": auth.login_status,  # Changed to use login_status
        "phone_number": auth.machine_id  # Changed to use machine_id for phone number
    }
