# SAMPLE FILE. This is how it should be done: secrets come from the
# environment, not from the file.
import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_TOKEN = os.getenv("API_TOKEN")
