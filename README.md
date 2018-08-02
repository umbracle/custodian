# Custodian

Custodian is a [Vault](https://www.vaultproject.io/) plugin to send ethereum transactions in a secure way.

Vault secures, stores and controls the access to different types of secrets. Custodian builts on top of that to store ethereum wallets and issue tokens that can be used to sign and send transaction on ethereum blockchains while the wallet private key is never exposed. The issued tokens can be renewed or revoked at any time.

## Usage

Refer to the install section for an explanation on how to install the plugin into Vault.

Add a keystore wallet into vault:

```
$ vault write custodian/wallets/wallet1 keystore=@wallet.json passphrase=password endpoint=https://kovan.infura.io
Success! Data written to: custodian/wallets/wallet1
```

The wallet private key will be stored into Vault and will only be accessible via the custodian plugin. 

You can query now the wallet created:

```
$ vault read custodian/wallets/wallet1
Address: 0x...
```

Next, create a credential to use the wallet. A credential issues a [lease](https://www.vaultproject.io/docs/concepts/lease.html) token which can be used to make transactions with the wallet.

```
$ vault read custodian/creds/wallet1
Key                Value
---                -----
lease_id           custodian/creds/wallet1/314a5d41-7316-03bb-0168-cf45c1396a69
lease_duration     1h
lease_renewable    true
id                 ce273c08-b0a1-20c9-1966-3fa7d745b017
```

To make a transaction, call the 'transaction' endpoint with the key from the credential step and the JSON transaction:

```
$ vault write custodian/transaction key=ce273c08-b0a1-20c9-1966-3fa7d745b017 data='{"to": "...", "value": "10"}'
Success! Data written to: custodian/wallets/a
Key      Value
---      -----
hash     0x...
```

It will return the hash of the transaction.

At any time, it is possible to revoke the lease token by running:

```
$ vault token revoke custodian/creds/wallet1/314a5d41-7316-03bb-0168-cf45c1396a69
```

After that, it will not be possible to use the key anymore to make transactions.

## Install

The following explanation to install the plugin has been take from [here](https://www.hashicorp.com/blog/building-a-vault-secure-plugin).

Create a temporary directory to compile the plugin into and to use as the plugin directory for Vault:

```
$ mkdir -p /tmp/vault-plugins
```

Compile the plugin into the temporary directory:

```
$ go build -o /tmp/vault-plugins/custodian
```

Create a configuration file to point Vault at this plugin directory:

```
$ tee /tmp/vault.hcl <<EOF
plugin_directory = "/tmp/vault-plugins"
EOF
```

Start a Vault server in development mode with the configuration:

```
$ vault server -dev -dev-root-token-id="root" -config=/tmp/vault.hcl
```

Leave this running and open a new tab or terminal window. Authenticate to Vault:

```
$ vault auth root
```

Calculate and register the SHA256 sum of the plugin in Vault's plugin catalog:

```
$ SHASUM=$(shasum -a 256 "/tmp/vault-plugins/custodian" | cut -d " " -f1)
$ vault write sys/plugins/catalog/custodian sha_256="$SHASUM" command="custodian"
```

Enable the auth plugin:

```
$ vault secrets enable -path=custodian -plugin-name=custodian plugin
```

After this step, the plugin can be accessible at the 'custodian' path.
