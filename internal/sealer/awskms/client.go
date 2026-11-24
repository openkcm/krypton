package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/securemem"
)

const (
	roleSessionName = "krypton"
	ciphertextKey   = "awskms-ciphertext"
	plaintextKey    = "awskms-plaintext"

	contextTenantKey = "tenant"
	contextAADKey    = "aad"
)

type kmsAPI interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type Client struct {
	kms kmsAPI
}

var _ sealer.Sealer = (*Client)(nil)

func NewClient(config Config, auth Auth) (*Client, error) {
	if err := config.ValidateSealerConfig(); err != nil {
		return nil, err
	}
	if err := auth.ValidateSealerAuth(); err != nil {
		return nil, err
	}
	return newClientFromConfig(aws.Config{Region: config.Region}, auth), nil
}

func newClientFromConfig(cfg aws.Config, auth Auth) *Client {
	cfg.Credentials = credentials.NewStaticCredentialsProvider(auth.Static.AccessKeyID, auth.Static.SecretAccessKey, "")
	cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(
		sts.NewFromConfig(cfg),
		auth.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = roleSessionName
			if auth.ExternalID != "" {
				o.ExternalID = aws.String(auth.ExternalID)
			}
		},
	))
	return &Client{kms: kms.NewFromConfig(cfg)}
}

func (c *Client) Seal(ctx context.Context, req sealer.SealRequest) (sealer.SealResponse, error) {
	keyARN, err := keyARNFromMetadata(req.Metadata)
	if err != nil {
		return sealer.SealResponse{}, err
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, hr *securemem.HandlerRequest) error {
		out, err := c.kms.Encrypt(ctx, &kms.EncryptInput{
			KeyId:             aws.String(keyARN),
			Plaintext:         req.Plaintext.SecureBytes(),
			EncryptionContext: encryptionContext(req.TenantID, req.AAD),
		})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEncrypt, err)
		}
		return keep(hr, ciphertextKey, out.CiphertextBlob)
	})
	if err != nil {
		return sealer.SealResponse{}, err
	}

	ciphertext, err := result(resp, ciphertextKey)
	if err != nil {
		return sealer.SealResponse{}, err
	}
	return sealer.SealResponse{Ciphertext: ciphertext}, nil
}

func (c *Client) Unseal(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
	keyARN, err := keyARNFromMetadata(req.Metadata)
	if err != nil {
		return sealer.UnsealResponse{}, err
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, hr *securemem.HandlerRequest) error {
		out, err := c.kms.Decrypt(ctx, &kms.DecryptInput{
			KeyId:             aws.String(keyARN),
			CiphertextBlob:    req.Ciphertext.SecureBytes(),
			EncryptionContext: encryptionContext(req.TenantID, req.AAD),
		})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDecrypt, err)
		}
		defer securemem.Zero(out.Plaintext)
		return keep(hr, plaintextKey, out.Plaintext)
	})
	if err != nil {
		return sealer.UnsealResponse{}, err
	}

	plaintext, err := result(resp, plaintextKey)
	if err != nil {
		return sealer.UnsealResponse{}, err
	}
	return sealer.UnsealResponse{Plaintext: plaintext}, nil
}

// KMS binds the ciphertext to this context, so Unseal must send exactly what Seal sent.
func encryptionContext(tenantID string, aad []byte) map[string]string {
	ec := map[string]string{}
	if tenantID != "" {
		ec[contextTenantKey] = tenantID
	}
	if len(aad) > 0 {
		ec[contextAADKey] = string(aad)
	}
	if len(ec) == 0 {
		return nil
	}
	return ec
}

func keyARNFromMetadata(metadata map[string]string) (string, error) {
	keyARN := metadata[sealer.ProviderKeyMetadataKey(TypeAwsKms)]
	if keyARN == "" {
		return "", ErrKeyARNMissing
	}
	return keyARN, nil
}

func keep(hr *securemem.HandlerRequest, name string, b []byte) error {
	d, err := hr.PersistentVault().Reserve(name, len(b))
	if err != nil {
		return err
	}
	copy(d, b)
	return nil
}

func result(resp *securemem.HandlerResponse, name string) (*securemem.Data, error) {
	d, ok := resp.MemVault().Get(name)
	if !ok {
		if err := resp.MemVault().DestroyAll(); err != nil {
			return nil, err
		}
		return nil, ErrResultMissing
	}
	return d, nil
}
