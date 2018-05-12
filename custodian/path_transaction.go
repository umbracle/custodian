package custodian

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	rpc "github.com/ethereum/go-ethereum/rpc"
)

func pathTransactions(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "transaction",
		Fields: map[string]*framework.FieldSchema{
			"data": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"id": &framework.FieldSchema{
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
	To           *common.Address
	Nonce        uint64
	NoncePending uint64
	GasPrice     *big.Int
	GasLimit     uint64
	Value        *big.Int
	Data         []byte
}

func UnmarshalTx(data []byte) (*Transaction, error) {

	type transaction struct {
		To       *common.Address `json:"to"`
		Nonce    uint64          `json:"nonce"`
		GasPrice *hexutil.Big    `json:"gasPrice"`
		GasLimit uint64          `json:"gas"`
		Value    *hexutil.Big    `json:"value"`
		Data     *hexutil.Bytes  `json:"data"`
	}

	var res transaction
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

	tx := &Transaction{
		To:       res.To,
		Nonce:    res.Nonce,
		GasPrice: res.GasPrice.ToInt(),
		GasLimit: res.GasLimit,
		Value:    res.Value.ToInt(),
		Data:     []byte{},
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
		return nil, fmt.Errorf("Key not found")
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

func (b *backend) send(wallet *wallet, tx *Transaction) (string, error) {
	b.txMutex.Lock()
	defer b.txMutex.Unlock()

	var err error
	client, err := rpc.Dial(wallet.Endpoint)
	if err != nil {
		return "", err
	}

	ethClient := ethclient.NewClient(client)

	privateKey, err := wallet.GetPrivateKey()
	if err != nil {
		return "", err
	}

	from := common.HexToAddress(wallet.Address)

	ctx := context.Background()

	// Nonce
	tx.Nonce, err = ethClient.NonceAt(ctx, from, nil)
	if err != nil {
		return "", err
	}

	// GasLimit
	if tx.GasLimit == 0 {
		msg := ethereum.CallMsg{From: from, To: tx.To, Data: tx.Data, Value: nil}
		if tx.GasLimit, err = ethClient.EstimateGas(ctx, msg); err != nil {
			return "", err
		}
	}

	// GasPrice
	if tx.GasPrice == nil {
		if tx.GasPrice, err = ethClient.SuggestGasPrice(ctx); err != nil {
			return "", err
		}
	}

	rawTx := types.NewTransaction(tx.Nonce, *tx.To, tx.Value, tx.GasLimit, tx.GasPrice, tx.Data)

	signed, err := types.SignTx(rawTx, types.HomesteadSigner{}, privateKey)
	if err != nil {
		return "", err
	}

	if err := ethClient.SendTransaction(ctx, signed); err != nil {
		return "", fmt.Errorf("%v. %d, %d", err, tx.Nonce, tx.NoncePending)
	}

	return signed.Hash().Hex(), nil
}

const pathTransactionsHelpSyn = `
Send the ethereum transaction
`

const pathTransactionsHelpDesc = ``
