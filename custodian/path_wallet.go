package custodian

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/umbracle/ethgo/keystore"
	"github.com/umbracle/ethgo/wallet"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type walletEntry struct {
	Address    string `mapstructure:"address" json:"address"`
	PrivateKey string `mapstructure:"private_key" json:"private_key"`
	Endpoint   string `mapstructure:"endpoint" json:"endpoint"`
}

func (w *walletEntry) GetPrivateKey() (*ecdsa.PrivateKey, error) {
	res1, err := hex.DecodeString(w.PrivateKey)
	if err != nil {
		return nil, err
	}
	priv, err := wallet.ParsePrivateKey(res1)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func pathWallets(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "wallets/" + framework.GenericNameRegex("wallet"),
		Fields: map[string]*framework.FieldSchema{
			"endpoint": {
				Type: framework.TypeString,
			},
			"wallet": {
				Type: framework.TypeString,
			},
			"keystore": {
				Type: framework.TypeString,
			},
			"passphrase": {
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathWalletsRead,
			logical.UpdateOperation: b.pathWalletsWrite,
		},

		HelpSynopsis:    pathWalletsHelpSyn,
		HelpDescription: pathWalletsHelpDesc,
	}
}

func keyToWallet(key *wallet.Key) *walletEntry {
	priv, _ := key.MarshallPrivateKey()

	return &walletEntry{
		Address:    key.Address().String(),
		PrivateKey: hex.EncodeToString(priv),
	}
}

func createWallet(d *framework.FieldData) (*walletEntry, error) {
	key, err := wallet.GenerateKey()
	if err != nil {
		return nil, err
	}
	return keyToWallet(key), nil
}

func keystoreWallet(d *framework.FieldData) (*walletEntry, error) {
	privKey, err := keystore.DecryptV3([]byte(d.Get("keystore").(string)), d.Get("passphrase").(string))
	if err != nil {
		return nil, err
	}
	key, err := wallet.NewWalletFromPrivKey(privKey)
	if err != nil {
		return nil, err
	}
	return keyToWallet(key), nil
}

func (b *backend) pathWalletsWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	walletName := d.Get("wallet").(string)
	if walletName == "" {
		return logical.ErrorResponse("missing wallet name"), nil
	}

	endpoint := d.Get("endpoint").(string)
	if endpoint == "" {
		return logical.ErrorResponse("missing RPC endpoint"), nil
	}

	var fn func(d *framework.FieldData) (*walletEntry, error)
	if _, ok := d.GetOk("keystore"); ok {
		fn = keystoreWallet
	} else {
		fn = createWallet
	}

	wallet, err := fn(d)
	if err != nil {
		return nil, err
	}

	wallet.Endpoint = endpoint

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("wallets/%s", walletName), wallet)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathWalletsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	wallet, err := b.getWallet(ctx, req.Storage, d.Get("wallet").(string))
	if err != nil {
		return nil, err
	}
	if wallet == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": wallet.Address,
		},
	}, nil
}

func (b *backend) getWallet(ctx context.Context, s logical.Storage, n string) (*walletEntry, error) {
	entry, err := s.Get(ctx, "wallets/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result walletEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

const pathWalletsHelpSyn = `
Creates a new wallet with a json keystore file and a passphrase
`

const pathWalletsHelpDesc = ``
