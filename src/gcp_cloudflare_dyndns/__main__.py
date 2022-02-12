
from google.cloud import secretmanager
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] :: %(filename)s:%(lineno)d :: %(message)s")


if __name__ == "__main__":
    logging.info("External IP check started")
