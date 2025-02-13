import base64
import requests
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

app = Flask(__name__)

class Encryption:
    @staticmethod
    def get_public_key_from_string(pem_key):
        """
        Load a public key directly from a PEM string.
        """
        return load_pem_public_key(pem_key.encode())

    @staticmethod
    def encrypt(data, public_key):
        """
        Encrypt the given data using the provided public key with PKCS#1 padding.
        """
        encrypted_data = public_key.encrypt(
            data.encode("utf-8"),
            padding.PKCS1v15()  # Matches Java's PKCS1Padding
        )
        return base64.b64encode(encrypted_data).decode("utf-8")

# Public key for "subgateway" (default)
PUBLIC_KEY_SUBGATEWAY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0fq90cuaLo0nmblrirzW
/V7gqs07qok9X0bz5MRj8TN1afuOieRrdknceCzKI3xGExfim5R02UjPvn2m7Ryo
u7SZEZ7P8uz50etyB0qdhItw1gdn3kt3Rs79H8KH9cjQCiLXNneylKSdcQp7oOy8
bpbUmGhpOCZMrSsDqf5Q1/WSsx3vv8NIn3C+mBkuvL1Wv4Z8B36bR+gyRaPDASTV
6aHPsx5ffU9cpI16x7YX4fBqVD/0692cThpURBDH175Dr6UHMYFMFNdtxjy86HLC
3+cDuueVpEkp7vCnixCvVia8tgiwCmxPUP0yLpKmVKxkqq4Km1HQHBp3ANxjAk8Q
zwIDAQAB
-----END PUBLIC KEY-----
"""

# Public key for "retailergateway"
PUBLIC_KEY_RETAILERGATEWAY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu/b3++XzGzMCjpwNEKsx
BqbZ7G3wr8dlHToyiKDDcf6jaxQezW/cELrIghv1Sp17ohZxfPt0ac1j+qqleUE+
3RRSfrvkZcBrHdNT9+WU650aS1QFII1YmpbZohdQ/EkIUjmaeuPM+iWcpDvwRQEK
Reos+gaNSJxVeIpYBjiFNi4mrL+s4GTUBM8tKP5VaMBK6lSThaQDObiLE58s5ROa
izh0uXPMnIZsmOIqnY5ksgXwb3q7AVmXoC+muQEI1Kt3e6MUW9A/Y8bScSqEL+D2
+yiNom60TWOKN5QWEeO14e5Qk6uWbU0x2d1VN2RhbZwG/ZJ6s2s6ROcGEwqre5gS
/wIDAQAB
-----END PUBLIC KEY-----
"""

CORPORATE_LOGIN_URL = "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/CorporateLogin/"
CLIENT_ID = "924726a273f72a75733787680810c4e4"
CLIENT_SECRET = "7154c95b3351d88cb31302f297eb5a9c"

@app.route("/login", methods=["POST"])
def corporate_login():
    try:
        # Parse request body
        data = request.get_json()
        msisdn = data.get("msisdn")
        pin = data.get("pin")

        if not msisdn or not pin:
            return jsonify({"error": "msisdn and pin are required"}), 400

        # Determine which public key to use based on msisdn
        if "@" in msisdn:
            public_key_pem = PUBLIC_KEY_RETAILERGATEWAY
            channel = "retailergateway"
        else:
            public_key_pem = PUBLIC_KEY_SUBGATEWAY
            channel = "subgateway"

        # Load the public key
        public_key = Encryption.get_public_key_from_string(public_key_pem)

        # Perform encryption to generate LoginPayload
        login_payload = Encryption.encrypt(f"{msisdn}:{pin}", public_key)

        # Call the Corporate Login API
        headers = {
            "X-IBM-Client-Id": CLIENT_ID,
            "X-IBM-Client-Secret": CLIENT_SECRET,
            "X-Channel": channel,
            "Content-Type": "application/json"
        }
        response = requests.post(CORPORATE_LOGIN_URL, json={"LoginPayload": login_payload}, headers=headers)

        # Map exact response and status code
        if response.status_code != 200:
            return jsonify({"error": "Corporate login failed", "details": response.json()}), response.status_code

        response_data = response.json()
        timestamp = response_data.get("Timestamp")

        if not timestamp:
            return jsonify({"error": "Timestamp missing in Corporate Login response", "details": response_data}), 500

        # Generate X-Hash-Value using /xhash logic
        payload = f"{msisdn}~{timestamp}"
        x_hash_value = Encryption.encrypt(payload, public_key)

        return jsonify({
            "LoginPayload": login_payload,
            "CorporateLoginResponse": response_data,
            "X-Hash-Value": x_hash_value
        }), 200

    except requests.exceptions.RequestException as req_error:
        return jsonify({"error": "Request to Corporate Login API failed", "details": str(req_error)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
