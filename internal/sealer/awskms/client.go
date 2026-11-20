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

const roleSessionName = "krypton"

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

	cfg := aws.Config{
		Region:      config.Region,
		Credentials: credentials.NewStaticCredentialsProvider(auth.Static.AccessKeyID, auth.Static.SecretAccessKey, ""),
	}
	cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(
		sts.NewFromConfig(cfg),
		auth.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = roleSessionName
		},
	))

	return &Client{kms: kms.NewFromConfig(cfg)}, nil
}

func (c *Client) Seal(ctx context.Context, req sealer.SealRequest) (sealer.SealResponse, error) {
	keyARN, err := keyARNFromMetadata(req.Metadata)
	if err != nil {
		return sealer.SealResponse{}, err
	}

	out, err := c.kms.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyARN),
		Plaintext: req.Plaintext.SecureBytes(),
	})
	if err != nil {
		return sealer.SealResponse{}, fmt.Errorf("%w: %w", ErrEncrypt, err)
	}

	ciphertext, err := toSecureData("awskms-ciphertext", out.CiphertextBlob)
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

	out, err := c.kms.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(keyARN),
		CiphertextBlob: req.Ciphertext.SecureBytes(),
	})
	if err != nil {
		return sealer.UnsealResponse{}, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	defer securemem.Zero(out.Plaintext)

	plaintext, err := toSecureData("awskms-plaintext", out.Plaintext)
	if err != nil {
		return sealer.UnsealResponse{}, err
	}
	return sealer.UnsealResponse{Plaintext: plaintext}, nil
}

func keyARNFromMetadata(metadata map[string]string) (string, error) {
	keyARN := metadata[sealer.ProviderKeyMetadataKey(TypeAwsKms)]
	if keyARN == "" {
		return "", ErrKeyARNMissing
	}
	return keyARN, nil
}

func toSecureData(name string, b []byte) (*securemem.Data, error) {
	d, err := securemem.NewData(name, len(b))
	if err != nil {
		return nil, err
	}
	copy(d.SecureBytes(), b)
	return d, nil
}
