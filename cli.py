import qrcode
from eth_account import Account
from web3 import Web3
import pyperclip
import os
import json
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend

# === Configuration réseau Binance Smart Chain (peut être ignorée en mode hors ligne) ===
bsc_rpc = "https://bsc-dataseed1.ninicoin.io/"
web3 = Web3(Web3.HTTPProvider(bsc_rpc))

usdt_contract_address = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955")
erc20_abi = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    }
]

usdt_contract = web3.eth.contract(address=usdt_contract_address, abi=erc20_abi)

# === Nonce tracking (cold wallet) ===
NONCE_FILE = "nonces.json"

def load_nonce_data():
    if not os.path.exists(NONCE_FILE):
        return {}
    with open(NONCE_FILE, "r") as f:
        return json.load(f)

def save_nonce_data(data):
    with open(NONCE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_stored_nonce(address):
    data = load_nonce_data()
    return data.get(address, 0)

def update_stored_nonce(address, new_nonce):
    data = load_nonce_data()
    data[address] = new_nonce
    save_nonce_data(data)

def update_next_once(address):
    print_qr("https://pointages-mobiles.eu/get_nonce.php?address=" + address)
    update_stored_nonce(address,int(input("Input new nonce please : ")))

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode()

def decrypt(encrypted_data: str, password: str) -> str:
    try:
        data = base64.b64decode(encrypted_data)
        salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except InvalidTag:
        return None  # Mot de passe incorrect ou données corrompues


# === Fonctions de base ===


def load_keys():
    Account.enable_unaudited_hdwallet_features()
    keys = []
    parts = d2.split()
    for i in range(nb):
        path = f"m/{parts[0]}'/{parts[1]}'/{parts[2]}'/{parts[3]}/{i}"
        acct = Account.from_mnemonic(mnemo, account_path=path)
        keys.append(acct.key.hex())
    return keys

def get_balances(address):
    try:
        bnb = web3.from_wei(web3.eth.get_balance(address), 'ether')
        usdt_raw = usdt_contract.functions.balanceOf(address).call()
        usdt = usdt_raw / 1e18
        return bnb, usdt
    except Exception:
        return "Erreur", "Erreur"

def print_qr(data):
    qr = qrcode.QRCode()
    qr.add_data(data)
    qr.make()
    qr.print_tty()

def show_address_qr(address):
    print(f"\nQR Code de l'adresse: {address}")
    print_qr(address)

def build_and_sign_tx(private_key, to_address, value_eth=0, token=False, token_amount=0):
    acct = Account.from_key(private_key)
    nonce = get_stored_nonce(acct.address)
    update_stored_nonce(acct.address, int(nonce) + 1)
    gas_price = web3.to_wei("0.1", "gwei")  # valeur fixe raisonnable

    if not token:
        tx = {
            "nonce": nonce,
            "to": Web3.to_checksum_address(to_address),
            "value": web3.to_wei(value_eth, 'ether'),
            "gas": 75000,
            "gasPrice": gas_price,
            "chainId": 56,
        }
    else:
        contract = usdt_contract
        decimals = 18
        amount = int(token_amount * 10 ** decimals)
        tx = contract.functions.transfer(
            Web3.to_checksum_address(to_address),
            amount
        ).build_transaction({
            "chainId": 56,
            "gas": 75000,
            "gasPrice": gas_price,
            "nonce": nonce,
        })

    signed_tx = acct.sign_transaction(tx)
    return signed_tx.raw_transaction.hex()

def send_bnb_flow(private_key):
    to_address = input("Adresse destinataire (BNB) : ").strip()
    amount = float(input("Montant BNB à envoyer : "))
    raw_tx = build_and_sign_tx(private_key, to_address, value_eth=amount, token=False)
    print("\n--- Transaction signée (raw hex) ---")
    print(raw_tx)
    print("\n--- QR Code de la transaction ---")
    print_qr("https://pointages-mobiles.eu/validator.php?tx=0x" + raw_tx)
    print("Scanne ce QR code pour broadcast la transaction depuis un autre appareil.")

def send_usdt_flow(private_key):
    to_address = input("Adresse destinataire (USDT) : ").strip()
    amount = float(input("Montant USDT à envoyer : "))
    raw_tx = build_and_sign_tx(private_key, to_address, token=True, token_amount=amount)
    print("\n--- Transaction signée (raw hex) ---")
    print(raw_tx)
    print("\n--- QR Code de la transaction ---")
    print_qr("https://pointages-mobiles.eu/validator.php?tx=0x" + raw_tx)
    print("Scanne ce QR code pour broadcast la transaction depuis un autre appareil.")

def show_wallets(private_keys):
    for idx, key in enumerate(private_keys):
        acct = Account.from_key(key)
        addr = acct.address
        #bnb, usdt = get_balances(addr)
        print(f"\n[{idx}] Adresse: {addr}")
        #print(f"     ➤ BNB  : {bnb}")
        #print(f"     ➤ USDT : {usdt}")

def wallet_actions(index, private_keys):
    key = private_keys[index]
    address = Account.from_key(key).address

    while True:
        print(f"\n🔧 Actions pour {address}:")
        print("[1] Afficher QR code adresse")
        print("[2] Copier adresse")
        print("[3] Envoyer BNB")
        print("[4] Envoyer USDT")
        print("[5] Forcer mise à jour du nonce (en ligne)")
        print("[0] Retour")
        choice = input(">> ")

        if choice == "1":
            show_address_qr(address)
        elif choice == "2":
            pyperclip.copy(address)
            print("✅ Adresse copiée dans le presse-papier.")
        elif choice == "3":
            send_bnb_flow(key)
        elif choice == "4":
            send_usdt_flow(key)
        elif choice == "5":
            update_next_once(address)
        elif choice == "0":
            break
        else:
            print("❌ Choix invalide.")

# === Lancement ===
if __name__ == "__main__":
    print(r"""  ______    ______   __        _______   __       __   ______   __        __        ________  ________ 
 /      \  /      \ /  |      /       \ /  |  _  /  | /      \ /  |      /  |      /        |/        |
/$$$$$$  |/$$$$$$  |$$ |      $$$$$$$  |$$ | / \ $$ |/$$$$$$  |$$ |      $$ |      $$$$$$$$/ $$$$$$$$/ 
$$ |  $$/ $$ |  $$ |$$ |      $$ |  $$ |$$ |/$  \$$ |$$ |__$$ |$$ |      $$ |      $$ |__       $$ |   
$$ |      $$ |  $$ |$$ |      $$ |  $$ |$$ /$$$  $$ |$$    $$ |$$ |      $$ |      $$    |      $$ |   
$$ |   __ $$ |  $$ |$$ |      $$ |  $$ |$$ $$/$$ $$ |$$$$$$$$ |$$ |      $$ |      $$$$$/       $$ |   
$$ \__/  |$$ \__$$ |$$ |_____ $$ |__$$ |$$$$/  $$$$ |$$ |  $$ |$$ |_____ $$ |_____ $$ |_____    $$ |   
$$    $$/ $$    $$/ $$       |$$    $$/ $$$/    $$$ |$$ |  $$ |$$       |$$       |$$       |   $$ |   
 $$$$$$/   $$$$$$/  $$$$$$$$/ $$$$$$$/  $$/      $$/ $$/   $$/ $$$$$$$$/ $$$$$$$$/ $$$$$$$$/    $$/    
                                                                                                      """)
    print("- Login to an existing account -> Choose 1")
    print("- Add an account -> Choose 2")
    inputX = input("Please input a number btw 1 -> 2 : ")

    if inputX == "2":
        mnemo = input("Mnemonic phrase : ").strip()
        d2 = input("Data 2 : ").strip()
        nb = int(input("Number of accounts : "))
        password = getpass("Choose a password : ")
        reenterpass = getpass("Please reenter your password : ")
        if password != reenterpass:
            print("Passwords do not match. Please retry")
            exit()
        data_to_store = json.dumps({"mnemo": mnemo, "d2": d2, "nb": nb})
        encrypted = encrypt(data_to_store, password)
        with open("vault.dat", "w") as f:
            f.write(encrypted)
        print("Data saved. Connecting..")

    elif inputX == "1":
        if not os.path.exists("vault.dat"):
            print("No accounts found, please create a new one. Thank you !")
            exit()

        for _ in range(3):
            password = getpass("Enter your password please : ")
            with open("vault.dat", "r") as f:
                encrypted = f.read()

            decrypted = decrypt(encrypted, password)
            if decrypted:
                data = json.loads(decrypted)
                mnemo = data["mnemo"]
                d2 = data["d2"]
                nb = data["nb"]
                print("Correct. Connecting ...")
                break
            else:
                print("incorrect pass")
        else:
            print("Closing after too much try")
            exit()

    else:
        print("Invalid Choice")
        exit()

    private_keys = load_keys()
    show_wallets(private_keys)

    while True:
        try:
            idx = int(input("\nChoisis un compte pour agir (-1 pour quitter) : "))
            if idx == -1:
                print("Bye!")
                break
            elif 0 <= idx < len(private_keys):
                wallet_actions(idx, private_keys)
            else:
                print("❌ Index invalide.")
        except ValueError:
            print("❌ Entrée invalide.")
