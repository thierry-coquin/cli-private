from flask import Flask, request, jsonify
from nacl.secret import SecretBox
from nacl.encoding import HexEncoder

app = Flask(__name__)

# ⚠️ Partage ce secret (32 bytes hex) avec le client seulement
SHARED_SECRET_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
box = SecretBox(bytes.fromhex(SHARED_SECRET_HEX))

@app.route("/sign", methods=["POST"])
def sign():
    try:
        encrypted = bytes.fromhex(request.json["data"])
        decrypted = box.decrypt(encrypted).decode()
        print("[📥] Reçu (déchiffré):", decrypted)

        # Simule la signature
        response_data = f"SIGNED({decrypted})"
        encrypted_response = box.encrypt(response_data.encode()).hex()
        return jsonify({"data": encrypted_response})

    except Exception as e:
        print("[❌] Erreur:", str(e))
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005)
