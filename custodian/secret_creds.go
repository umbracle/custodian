package custodian

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const SecretCredsType = "creds"

func secretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretCredsType,
		Fields: map[string]*framework.FieldSchema{
			"id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Cert token",
			},
		},
		Renew:  b.secretCredsRenew,
		Revoke: b.secretCredsRevoke,
	}
}

func (b *backend) secretCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}

	resp.Secret.TTL = time.Duration(10 * time.Hour)
	resp.Secret.MaxTTL = time.Duration(10 * time.Hour)
	return resp, nil
}

func (b *backend) secretCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	idRaw, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing internal data")
	}
	id, ok := idRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing internal data")
	}

	salt, err := b.Salt(ctx)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Delete(ctx, "creds/"+salt.SaltID(id))
	if err != nil {
		return nil, err
	}
	return nil, nil
}
