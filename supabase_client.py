import os
from dotenv import load_dotenv          # loads environment variables from the .env file
from supabase import create_client      # imports the Supabase client constructor

load_dotenv()  # This loads the .env file

url = os.getenv("SUPABASE_URL")           # Retrieves the supabase project URL from environment variables
key = os.getenv("SUPABASE_KEY")           # retrieves the supabase API key from environment variables

# initializes the Supabase client for database operations
supabase = create_client(url, key)
