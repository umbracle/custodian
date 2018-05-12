package custodian

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type backend struct {
	*framework.Backend
	view      logical.Storage
	salt      *salt.Salt
	saltMutex sync.RWMutex
	txMutex   *sync.Mutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	var b backend
	b.Backend = &framework.Backend{
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"transaction",
			},
			LocalStorage: []string{
				"otp/",
			},
		},
		Paths: []*framework.Path{
			pathTransactions(&b),
			pathWallets(&b),
			pathCreds(&b),
		},
		Secrets: []*framework.Secret{
			secretCreds(&b),
		},
		BackendType: logical.TypeLogical,
	}

	b.txMutex = &sync.Mutex{}
	return &b, nil
}

func (b *backend) Salt(ctx context.Context) (*salt.Salt, error) {
	b.saltMutex.RLock()
	if b.salt != nil {
		defer b.saltMutex.RUnlock()
		return b.salt, nil
	}
	b.saltMutex.RUnlock()
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	if b.salt != nil {
		return b.salt, nil
	}
	salt, err := salt.NewSalt(ctx, b.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	b.salt = salt
	return salt, nil
}
