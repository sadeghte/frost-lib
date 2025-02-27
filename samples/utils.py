
import requests


def get_base_url(network='testnet'):
    return f"https://mempool.space/{network}/api"

def get_utxos(address, network="testnet"):
    url = f"{get_base_url(network)}/address/{address}/utxo"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        if data:
            return data
        else:
            raise Exception(f"No UTXOs found for address {address}.")
    else:
        raise Exception(f"Error: {response.status_code}, {response.text}")


def broadcast_tx(raw_tx: str, network='testnet'):
    url = f"{get_base_url(network)}/tx"
    response = requests.post(url, data=raw_tx, headers={
                             "Content-Type": "text/plain"})
    return response.text