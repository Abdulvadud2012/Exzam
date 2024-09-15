from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import List, Optional





# OAuth2PasswordBearer is used for authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = ""
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

db = {
    "tim": {
        "username": "tim",
        "full_name": "Tim Ruscica",
        "email": "tim@gmail.com",
        "hashed_password": "$2b$12$HxWHkvMuL7WrZad6lcCfluNFj1/Zp63lvP5aUrKlSTYtoFzPXHOtu",
        "disabled": False
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str or None = None


class User(BaseModel):
    username: str
    email: str or None = None
    full_name: str or None = None
    disabled: bool or None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False

    return user


def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception

        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception

    user = get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception

    return user


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": 1, "owner": current_user}]


# Sample data storage
posts = [
    {
        "id": 1,
        "title": "First News Post",
        "description": "This is the description of the first news.",
        "category": "Tech",
        "images": ["image1_url", "image2_url"],
        "comments": [],
        "created_at": "2024-09-12"
    },
    {
        "id": 2,
        "title": "Second News Post",
        "description": "This is the description of the second news.",
        "category": "Science",
        "images": ["image3_url", "image4_url"],
        "comments": [],
        "created_at": "2024-09-11"
    }
]

# Models for API
class Post(BaseModel):
    title: str
    category: str
    images: List[str]

class FullPost(Post):
    description: str
    comments: List[str]
    created_at: str

class Comment(BaseModel):
    text: str

# Public route: Get a list of posts with limited data
@app.get("/posts", response_model=List[Post])
def get_posts():
    return [{"title": post["title"], "category": post["category"], "images": [post["images"][0]]} for post in posts]

# Public route: Get full post details by ID
@app.get("/posts/{post_id}", response_model=FullPost)
def get_post(post_id: int):
    post = next((post for post in posts if post["id"] == post_id), None)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post

# Authorized route: Add comment to a post
@app.post("/posts/{post_id}/comment")
def add_comment(post_id: int, comment: Comment, token: str = Depends(oauth2_scheme)):
    post = next((post for post in posts if post["id"] == post_id), None)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    post["comments"].append(comment.text)
    return {"message": "Comment added"}

# Authorized route: Save post (just a placeholder)
@app.get("/posts/{post_id}/save")
def save_post(post_id: int, token: str = Depends(oauth2_scheme)):
    # Logic for saving the post to favorites can be added here
    return {"message": "Post saved to favorites"}


# Sample data
users = [
    {"id": 1, "username": "user1", "saved_posts": []},
    {"id": 2, "username": "user2", "saved_posts": []}
]

posts = [
    {
        "id": 1,
        "title": "First News Post",
        "description": "Description of the first news.",
        "category": "Tech",
        "images": ["image1_url", "image2_url"],
        "comments": [],
        "created_at": "2024-09-12"
    },
    {
        "id": 2,
        "title": "Second News Post",
        "description": "Description of the second news.",
        "category": "Science",
        "images": ["image3_url", "image4_url"],
        "comments": [],
        "created_at": "2024-09-11"
    }
]

class Comment(BaseModel):
    user_id: int
    text: str

# Model for Post and FullPost remains unchanged from previous examples

# Fetch current user (simplified for demo purposes)
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = next((u for u in users if f"user{u['id']}" in token), None)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user

# Add comment to a post
@app.post("/posts/{post_id}/comment")
def add_comment(post_id: int, comment: Comment, user: dict = Depends(get_current_user)):
    post = next((post for post in posts if post["id"] == post_id), None)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Add comment to the post
    post["comments"].append({
        "user_id": comment.user_id,
        "text": comment.text,
        "created_at": datetime.now().isoformat()
    })
    return {"message": "Comment added"}

# Save a post to user's favorites
@app.post("/posts/{post_id}/save")
def save_post(post_id: int, user: dict = Depends(get_current_user)):
    post = next((post for post in posts if post["id"] == post_id), None)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if post_id in user['saved_posts']:
        raise HTTPException(status_code=400, detail="Post already saved")
    
    # Save the post to user's favorites
    user['saved_posts'].append(post_id)
    return {"message": "Post saved"}

# Get user's saved posts
@app.get("/users/{user_id}/saved_posts")
def get_saved_posts(user_id: int, user: dict = Depends(get_current_user)):
    if user_id != user['id']:
        raise HTTPException(status_code=403, detail="Access denied")

    saved_posts = [post for post in posts if post['id'] in user['saved_posts']]
    return saved_posts




# Sample data for users and posts
users = [
    {"id": 1, "username": "user1", "saved_posts": []},
    {"id": 2, "username": "user2", "saved_posts": []}
]

posts = [
    {
        "id": 1,
        "title": "First News Post",
        "description": "Description of the first news.",
        "category": "Tech",
        "images": ["image1_url", "image2_url"],
        "comments": [],
        "created_at": "2024-09-12"
    },
    {
        "id": 2,
        "title": "Second News Post",
        "description": "Description of the second news.",
        "category": "Science",
        "images": ["image3_url", "image4_url"],
        "comments": [],
        "created_at": "2024-09-11"
    }
]

class Comment(BaseModel):
    text: str

# Fetch current user (simplified for demo purposes)
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = next((u for u in users if f"user{u['id']}" in token), None)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user

# Public route: Get a list of posts with limited data
@app.get("/posts")
def get_posts():
    return [{"title": post["title"], "category": post["category"], "images": [post["images"][0]]} for post in posts]

# Public route: Get full post details by ID
@app.get("/posts/{post_id}")
def get_post(post_id: int):
    post = next((post for post in posts if post["id"] == post_id), None)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post

# Authorized route: Add comment to a post
@app.post("/posts/{post_id}/comment")
def add_comment(post_id: int, comment: Comment, token: str = Depends(oauth2_scheme)):
    # Fetch the current user
    user = get_current_user(token)

    post = next((post for post in posts if post["id"] == post_id), None)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Add the comment to the post
    post["comments"].append({
        "user_id": user['id'],
        "text": comment.text,
        "created_at": datetime.now().isoformat()
    })
    return {"message": "Comment added"}

# Unauthorized users trying to comment
@app.post("/posts/{post_id}/comment/unauthorized")
def unauthorized_comment():
    raise HTTPException(status_code=403, detail="You must be logged in to comment.")
