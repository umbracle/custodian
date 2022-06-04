package custodian

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/jsonrpc"
	"github.com/umbracle/ethgo/wallet"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathTransactions(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "transaction",
		Fields: map[string]*framework.FieldSchema{
			"data": {
				Type: framework.TypeString,
			},
			"id": {
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTransactionsWrite,
		},

		HelpSynopsis:    pathTransactionsHelpSyn,
		HelpDescription: pathTransactionsHelpDesc,
	}
}

type Transaction struct {
	To           *ethgo.Address
	Nonce        uint64
	NoncePending uint64
	GasPrice     uint64
	GasLimit     uint64
	Value        *big.Int
	Data         []byte
}

func UnmarshalTx(data []byte) (*Transaction, error) {
	type transaction struct {
		To       *ethgo.Address  `json:"to"`
		Nonce    uint64          `json:"nonce"`
		GasPrice *ethgo.ArgBig   `json:"gasPrice"`
		GasLimit uint64          `json:"gas"`
		Value    *ethgo.ArgBig   `json:"value"`
		Data     *ethgo.ArgBytes `json:"data"`
	}

	var res transaction
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

	tx := &Transaction{
		To:       res.To,
		Nonce:    res.Nonce,
		GasLimit: res.GasLimit,
		Data:     []byte{},
	}
	if res.GasPrice != nil {
		tx.GasPrice = (*big.Int)(res.GasPrice).Uint64()
	}
	if res.Value != nil {
		tx.Value = (*big.Int)(res.Value)
	}

	if res.Data != nil {
		tx.Data = *res.Data
	}

	return tx, nil
}

func (b *backend) pathTransactionsWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key := d.Get("id").(string)

	salt, err := b.Salt(ctx)
	if err != nil {
		return nil, err
	}
	keySalted := salt.SaltID(key)

	cred, err := b.getCredential(ctx, req.Storage, keySalted)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("key not found")
	}

	wallet, err := b.getWallet(ctx, req.Storage, cred.Wallet)
	if err != nil {
		return nil, err
	}

	tx, err := UnmarshalTx([]byte(req.Get("data").(string)))
	if err != nil {
		return nil, err
	}

	hash, err := b.send(wallet, tx)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"hash": hash,
		},
	}, nil
}

func (b *backend) send(entry *walletEntry, tx *Transaction) (string, error) {
	b.txMutex.Lock()
	defer b.txMutex.Unlock()

	client, err := jsonrpc.NewClient(entry.Endpoint)
	if err != nil {
		return "", err
	}

	privateKey, err := entry.GetPrivateKey()
	if err != nil {
		return "", err
	}
	key := wallet.NewKey(privateKey)

	from := ethgo.HexToAddress(entry.Address)

	// chainid
	chainID, err := client.Eth().ChainID()
	if err != nil {
		return "", err
	}

	// Nonce
	tx.Nonce, err = client.Eth().GetNonce(from, ethgo.Latest)
	if err != nil {
		return "", err
	}

	// GasLimit
	if tx.GasLimit == 0 {
		msg := &ethgo.CallMsg{
			From:  from,
			To:    (*ethgo.Address)(tx.To),
			Data:  tx.Data,
			Value: nil,
		}
		if tx.GasLimit, err = client.Eth().EstimateGas(msg); err != nil {
			return "", err
		}
	}

	// GasPrice
	if tx.GasPrice == 0 {
		if tx.GasPrice, err = client.Eth().GasPrice(); err != nil {
			return "", err
		}
	}

	txn := &ethgo.Transaction{
		Nonce: tx.Nonce,
	}
	signer := wallet.NewEIP155Signer(chainID.Uint64())
	signedTxn, err := signer.SignTx(txn, key)
	if err != nil {
		return "", err
	}

	txnRaw, err := signedTxn.MarshalRLPTo(nil)
	if err != nil {
		return "", err
	}
	hash, err := client.Eth().SendRawTransaction(txnRaw)
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

const pathTransactionsHelpSyn = `
Send the ethereum transaction
`

const pathTransactionsHelpDesc = ``
