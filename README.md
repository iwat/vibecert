# vibecert
Vibe Coding meets Certificate Management 💥🔐

## Usage

First, create the required directory structure.

```
mkdir -p data/certs
mkdir -p data/keys
```

### Creating a root certificate

```
$ vibecert create-root --cn 'Family CA V1' --org 'My Family' --country CA
Enter password to encrypt private key:
Root certificate and key generated successfully:
  Private key: data/keys/7bf09aea9e8e03f0fbe5dc0c4083d985.key (encrypted)
  Certificate: data/certs/7bf09aea9e8e03f0fbe5dc0c4083d985.crt
  Serial number: 7bf09aea9e8e03f0fbe5dc0c4083d985
  Key type: ecc
  Valid for: 3650 days
```

### Creating an intermediate certificate

```
$ vibecert create-intermediate -ca-serial 7bf09aea9e8e03f0fbe5dc0c4083d985 --cn 'Family Intermediate CA V1' --org 'My Family' --country CA
Enter password for parent CA private key:
Enter password to encrypt new intermediate private key:
Intermediate CA certificate and key generated successfully:
  Private key: data/keys/f353d6ba0fe5f333eb2448698758f9e6.key (encrypted)
  Certificate: data/certs/f353d6ba0fe5f333eb2448698758f9e6.crt
  Serial number: f353d6ba0fe5f333eb2448698758f9e6
  Parent CA: 7bf09aea9e8e03f0fbe5dc0c4083d985
  Key type: ecc
  Valid for: 1825 days
  Path length constraint: 0
```

### Create a client mTLS certificate

```
$ vibecert create-leaf -ca-serial f353d6ba0fe5f333eb2448698758f9e6 --cn "Dad's iPhone 15" --org 'My Family' --country CA -client-auth
Enter password for parent CA private key:
Enter password to encrypt new leaf private key:
End-entity certificate and key generated successfully:
  Private key: data/keys/ab0d2b0906783305e668562be2f4f8e8.key (encrypted)
  Certificate: data/certs/ab0d2b0906783305e668562be2f4f8e8.crt
  Serial number: ab0d2b0906783305e668562be2f4f8e8
  Parent CA: f353d6ba0fe5f333eb2448698758f9e6
  Key type: ecc
  Valid for: 365 days
```
