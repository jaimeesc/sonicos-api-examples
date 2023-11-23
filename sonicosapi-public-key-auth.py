import re
import base64
import argparse
from urllib3.exceptions import InsecureRequestWarning
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ModuleNotFoundError:
    print("Cryptography module not found. Try 'pip install cryptography'.")
    exit(1)
try:
    import requests
except ModuleNotFoundError:
    print("Requests module not found. Try 'pip install requests'.")
    exit(1)


# Disable SSL/TLS-related warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Argument parsing.
parser = argparse.ArgumentParser(description='SonicOS API Public Key Authentication example script.')
parser.add_argument('--address', required=True, help='IP/FQDN of the target firewall.')
parser.add_argument('--user', required=True, help='Firewall management username.')
parser.add_argument('--password', required=True, help='Firewall management password.')
parser.add_argument('--preempt', required=False, action='store_true', help='Override/Preempt current management session.')

args = parser.parse_args()

sw_user = args.user
sw_password = args.password
url = f"https://{args.address}/api/sonicos"

print("Notes: Enable Public Key Authentication, set RSA padding type to 'PKCS#1 v2.0 OAEP', and OAEP settings to SHA-256.")
print("Refer to https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-device_settings/Content/Topics/Audit_SonicOS_API/SonicOS-API-enabling.htm/ for information on how to enable SonicOS API and configure authentication methods.\n")


def show_response_info(resp):
    if response.status_code == 200:
        # Print the HTTP response details
        print(response.json())
    else:
        print(response.status_code)
        print(response.headers)
        print(response.text)
        print(response.request.headers)


print("\nSending a POST to /api/sonicos/auth to retrieve the public key from the WWW-Authenticate header. Saving it to 'SWPEMFILE'.")
if args.preempt:
    print("Preempt/Override is enabled.")
    response = requests.post(url + "/auth", json={'override': True}, verify=False)
else:
    response = requests.post(url + "/auth", verify=False)

# Check if the request was successful (HTTP status code 2xx)
if response.status_code == 401 or response.status_code == 200:
    # Extract the public key from the response headers
    auth_header = response.headers.get('WWW-Authenticate')
    public_key_match = re.search(r'key="(.+)"', auth_header)

    if public_key_match:
        public_key = public_key_match.group(1)

        # Format the public key and save it to pk.pem
        formatted_public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
        with open("pk.pem", "w") as file:
            file.write(formatted_public_key)
        print("Public key saved to pk.pem\n")
    else:
        print("Public key not found in the WWW-Authenticate header.\n")
else:
    print(f"Error: HTTP status code {response.status_code}\n")
    print(response.text)
    print()


print("Loading the public key data.\n")

# Read the public key from the pk.pem file
with open("pk.pem", "rb") as key_file:
    public_key_data = key_file.read()

# Load the public key
public_key = serialization.load_pem_public_key(public_key_data, default_backend())

if isinstance(public_key, rsa.RSAPublicKey):
    print("PEM Public Key is an RSAPublicKey.")

# Encrypt the password using RSA OAEP.
cipher = public_key.encrypt(
    sw_password.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Base64 encode the encrypted password.
encoded_cipher = base64.b64encode(cipher).decode('utf-8')

# Build the Authorization header with the management username and CIPHER. Authenticate to SonicOS API.
authorization_header = f'SNWL-PK-AUTH user="{sw_user}", data="{encoded_cipher}"'

print("\nSending POST with username and cipher data.")
response = requests.post(url + "/auth", headers={'Authorization': authorization_header}, verify=False)
show_response_info(response)

print("\n\n")

# Switch to config mode. Likely already in config mode.
response = requests.post(url + "/start-management", verify=False)
show_response_info(response)

# Get current SonicOS version info.
response = requests.get(url + "/version", verify=False)
show_response_info(response)
    