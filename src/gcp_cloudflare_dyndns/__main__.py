import sys
from google.cloud import secretmanager
import logging
import os
from dotenv import dotenv_values
import requests
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] :: %(filename)s:%(lineno)d :: %(message)s",
)


if __name__ == "__main__":
    logging.info("External IP check started")

    # Load config. Precedence (increasing order): .env, .env.local, environment variables.
    config = {**dotenv_values(".env"), **dotenv_values(".env.local"), **os.environ}

    # Let's go get our secret token from GCP using the info provided
    # in the environ.
    try:
        cloudflare_token_secret = config["CF_API_SECRET_NAME"]
    except KeyError:
        logging.error("No Cloudflare API secret name was provided.")
        sys.exit(1)

    secret_client = secretmanager.SecretManagerServiceClient()
    response = secret_client.access_secret_version(
        request={"name": cloudflare_token_secret}
    )

    try:
        cf_api_info = json.loads(response.payload.data.decode("UTF-8"))
    except UnicodeDecodeError:
        logging.exception("Could not decode response payload")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.exception("Invalid JSON object found in secret.")
        sys.exit(1)

    # Now let's make a call to Cloudflare to check the A record it's got for us
    try:
        zone_id = cf_api_info["cf_zone_id"]
        record_id = cf_api_info["cf_record_id"]
        api_token = cf_api_info["cf_api_token"]
    except KeyError:
        logging.error(
            "Malformed JSON in secret. requires cf_api_token, cf_zone_id and cf_record_id to be set."
        )
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer: {api_token}",
        "Content-Type": "application/json",
    }
    a_record = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers=headers,
    )
    try:
        a_record.raise_for_status()
        a_record = a_record.json()
    except:
        logging.exception("Could not make CF API request")
        sys.exit(1)

    currently_set_ip = a_record["result"]["content"]

    vm_ip = requests.get(
        "http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
    )

    try:
        vm_ip.raise_for_status()
    except:
        logging.exception("Could not contact GCP IMDS")
        sys.exit(1)

    vm_ip = vm_ip.text

    # If the IP addresses don't match, make sure we're going with the VM IP.
    if vm_ip != currently_set_ip:
        # The "Payload" is what we want to change in the DNS record JSON (in this case, it's our IP)
        payload = {"content": vm_ip}
        set_ip_req = requests.patch(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
            headers=headers,
            data=json.dumps(payload),
        )

        try:
            set_ip_req.raise_for_status()
        except:
            logging.exception("Could not set VM IP address")
            sys.exit(1)
    else:
        logging.info("IP is unchanged.")
