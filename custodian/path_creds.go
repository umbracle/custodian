package custodian

import (
	"context"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsRead,
		},

		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

type credential struct {
	Wallet string `json:"wallet" structs:"wallet" mapstructure:"wallet"`
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	if _, err := b.getWallet(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	credential := &credential{
		Wallet: name,
	}

	cred, err := b.GenerateCredential(ctx, req, credential)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(SecretCredsType).Response(map[string]interface{}{
		"id": cred,
	}, map[string]interface{}{
		"id": cred,
	})

	// TODO. Remove hardcoded
	resp.Secret.TTL = time.Duration(1 * time.Hour)
	resp.Secret.MaxTTL = time.Duration(1 * time.Hour)

	return resp, nil
}

func (b *backend) getCredential(ctx context.Context, s logical.Storage, n string) (*credential, error) {
	entry, err := s.Get(ctx, "creds/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result credential
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) GenerateSaltedCredential(ctx context.Context) (string, string, error) {
	str, err := uuid.GenerateUUID()
	if err != nil {
		return "", "", err
	}
	salt, err := b.Salt(ctx)
	if err != nil {
		return "", "", err
	}

	return str, salt.SaltID(str), nil
}

func (b *backend) GenerateCredential(ctx context.Context, req *logical.Request, credential *credential) (string, error) {
	cred, credSalted, err := b.GenerateSaltedCredential(ctx)
	if err != nil {
		return "", err
	}

	entry, err := logical.StorageEntryJSON("creds/"+credSalted, credential)
	if err != nil {
		return "", err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return "", err
	}
	return cred, nil
}

const pathCredsHelpSyn = `
Creates a credential for sending ethereum transactions with a wallet
`

const pathCredsHelpDesc = ``
