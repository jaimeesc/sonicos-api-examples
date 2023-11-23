#!/bin/bash

#SWADDRESS=192.168.168.168
#SWUSER=admin
#SWPASSWORD=password

echo "Notes: Enable Public Key Authentication, set RSA padding type to 'PKCS#1 v2.0 OAEP', and OAEP settings to SHA-256."
echo "Refer to https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-device_settings/Content/Topics/Audit_SonicOS_API/SonicOS-API-enabling.htm/ for information on how to enable SonicOS API and configure authentication methods."
echo " "

# Check if the SWADDRESS variable is set
if [ -z "$SWADDRESS" ]; then
    # If not set, prompt the user to input SWUSER
    read -p "Enter the SonicWall firewall address: " SWADDRESS
fi

# Check if the SWUSER variable is set
if [ -z "$SWUSER" ]; then
    # If not set, prompt the user to input SWUSER
    read -p "Enter the SonicWall management username: " SWUSER
fi

# Check if the SWPASSWORD variable is set
if [ -z "$SWPASSWORD" ]; then
    # If not set, prompt the user to input SWPASSWORD
    read -s -p "Enter the password for $SWUSER: " SWPASSWORD
    echo    # Add a newline after the password input
fi


SWCURRENT_DIRECTORY=$(pwd)
SWPEMFILE='$SWCURRENT_DIRECTORY/pk.pem'
echo "Sending a POST to /api/sonicos/auth to retrieve the public key from the WWW-Authenticate header. Saving it to '$SWPEMFILE'."
curl -k -i -s -X POST https://$SWADDRESS/api/sonicos/auth | grep 'WWW-Authenticate: SNWL-PK-AUTH' | sed -e 's/^.*key="/-----BEGIN PUBLIC KEY-----\n/' -e 's/"/\n-----END PUBLIC KEY-----/' > pk.pem

echo "Encrypting the password with OAEP padding using SHA-256."
CIPHER=$(echo -n "$SWPASSWORD" | openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -pubin -inkey pk.pem | base64 -w 0)
echo $CIPHER

echo "Sending a POST to /api/sonicos/auth with the Authorization header and cipher data."
curl -k -i -s -H 'Authorization: SNWL-PK-AUTH user="'$SWUSER'", data="'$CIPHER'"' -X POST https://$SWADDRESS/api/sonicos/auth


curl -k -i -s GET https://$SWADDRESS/api/sonicos/version

#curl -k -i -s GET https://$SWADDRESS/api/sonicos/
