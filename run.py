# run.py
from app import create_app
import os
import logging


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = create_app()

if __name__ == "__main__":
    logger.info(f"Starting application with CACHE_VERSION: {app.config['CACHE_VERSION']}")
    logger.info(f"Application running in debug mode: {app.config['DEBUG']}")
    logger.info(f"Application host: {app.config['HOST']}")
    logger.info(f"Application port: {app.config['PORT']}")
    app.run(debug=app.config['DEBUG'], host=app.config['HOST'], port=app.config['PORT'])
    