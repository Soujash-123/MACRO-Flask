import os
import uuid
from pymongo import MongoClient
from gridfs import GridFS
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB Connection
uri = "mongodb+srv://oppurtunest:hAPV3Tf0QoB0GgiQ@cluster0.mbbgm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

try:
    client = MongoClient(uri)
    db = client['MACRO-users']
    users_collection = db['users']
    keys_collection = db['encryption_keys']
    posts_collection = db['posts']
    fs = GridFS(db)

    # Create indexes
    users_collection.create_index('username', unique=True)
    users_collection.create_index('email', unique=True)
    keys_collection.create_index('user_id', unique=True)
    posts_collection.create_index([('created_at', -1)])

    logger.info("Connected to MongoDB and indexes created.")

except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}")
    raise

def upload_file(file_path, session, post_type, content=None):
    """
    Upload an image or audio file to MongoDB and store its metadata in the posts collection.

    :param file_path: Path to the file to upload
    :param session: Session dictionary containing 'user_id' and 'username'
    :param post_type: Type of the post (e.g., 'image', 'audio', 'text', etc.)
    :param content: Additional content or text related to the post
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Ensure session contains required fields
        if 'user_id' not in session or 'username' not in session:
            raise ValueError("Session must contain 'user_id' and 'username'.")

        file_id = None
        file_name = os.path.basename(file_path)
        
        # Read the file content and upload it to GridFS if file_path is provided
        with open(file_path, 'rb') as file_data:
            file_id = fs.put(file_data, filename=file_name, content_type=post_type)
        
        # Prepare the post metadata
        post_metadata = {
            "post_id": str(uuid.uuid4()),
            "user_id": session['user_id'],
            "username": session['username'],
            "type": post_type,
            "content": content if content else "",
            "file_id": str(file_id) if file_id else None,
            "created_at": datetime.utcnow(),
            "likes": 0,
            "comments": []
        }
        
        # Insert metadata into the posts collection
        posts_collection.insert_one(post_metadata)
        logger.info(f"Post created successfully. Post ID: {post_metadata['post_id']}")
    
    except Exception as e:
        logger.error(f"Failed to upload file and create post: {str(e)}")
        raise

# Example usage
if __name__ == "__main__":
    # Replace with actual file path and session details
    file_path = "path/to/your/file.jpg"  # or "path/to/your/audio.mp3"
    session = {
        "user_id": "877498dd-5bc1-4a04-9c81-f2004639b288",
        "username": "Soujash Banerjee"
    }
    post_type = "image"  # or "audio"
    content = "This is a sample post."

    upload_file(file_path, session, post_type, content)
