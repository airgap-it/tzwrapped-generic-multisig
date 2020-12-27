Generic SmartPy Multi Signature SmartContract
====================================



Build/Basic Usage
-----------------

## SmartPy Online IDE Development

You can simply copy/paste the raw payload/code from generic_multisig.py to https://smartpy.io/ide 

## Local Development

### Dependencies

This project depends only on SmartPy, you can install SmartPy by doing a:

```
$ curl -s https://SmartPy.io/dev/cli/SmartPy.sh -o /tmp/SmartPy.sh
$ chmod +x /tmp/SmartPy.sh
$ /tmp/SmartPy.sh local-install-auto smartpy
```

### Build

```
$ ./smartpy/SmartPy.sh compile generic_multisig.py "Executor(sp.nat(2), [alice.public_key, bob.public_key, dan.public_key])" out
```

### Test
```
$ ./smartpy/SmartPy.sh test generic_multisig.py out
```