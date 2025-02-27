## Installation
before running examples install current package locally.

```bash
$ pip install .
```

## Run
Run all examples from root directory

**Create master key**
```bash
$ python samples/sample-frost-dkg.py <key-file-name> <threshold> <num-signers>

# example
$ python samples/sample-frost-dkg.py wallet-1 2 3
```

**Spend BTC utxos in master key address**
```bash
$ python samples/sample-btc-tx-normal.py <key-file-name>

# example
$ python samples/sample-btc-tx-normal.py wallet-1
```

**Spend BTC utxos in tweaked address**
```bash
$ python samples/sample-btc-tx-tweak.py <key-file-name>

# example
$ python samples/sample-btc-tx-tweak.py wallet-1
```