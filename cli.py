import qrcode
from eth_account import Account
from web3 import Web3
import pyperclip
import os
import json

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
    qr.print_ascii()

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
    mnemo = input("Phrase mnémonique : ").strip()
    d2 = input("Chemin de dérivation (ex: 44 60 0 0) : ").strip()
    nb = int(input("Nombre de comptes à générer : "))

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
