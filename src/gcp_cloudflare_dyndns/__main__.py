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
        cloudflare_token_secret = config["CF_API_TOKEN_SECRET"]
    except KeyError:
        logging.error("No Cloudflare API token was provided.")
        sys.exit(1)

    secret_client = secretmanager.SecretManagerServiceClient()
    response = secret_client.access_secret_version(request=cloudflare_token_secret)

    cf_api_token = response.payload.data.decode("UTF-8")

    # Now let's make a call to Cloudflare to check the A record it's got for us
    try:
        zone_id = config["CF_ZONE_ID"]
        record_id = config["CF_RECORD_ID"]
    except KeyError:
        logging.error(
            "Could not get zone and/or record id. requires CF_ZONE_ID and CF_RECORD_ID to be set."
        )
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer: {cf_api_token}",
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
