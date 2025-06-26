import argparse  # noqa
import os  # noqa

import uvicorn
from dotenv import find_dotenv, load_dotenv  # noqa

# Load environment variables from .env file if present
load_dotenv(find_dotenv(raise_error_if_not_found=False))  # noqa

from main import backend  # noqa

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--development", action="store_true")
    args = parser.parse_args()

    # Set host to localhost in development mode, otherwise bind to all interfaces
    host = "localhost" if args.development else "0.0.0.0"
    # Start the uvicorn server with the backend app
    uvicorn.run(backend, host=host, port=8080)