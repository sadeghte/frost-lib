import support.py.frost_lib as frost;

secret = "0000000000000000000000000000000000000000000000000000000000000001"
result = frost.keys_split(secret, 3, 2)
print(result)

