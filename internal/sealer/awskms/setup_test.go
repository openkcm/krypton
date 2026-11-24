package awskms

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	emulatorPort    = "9297"
	emulatorDataDir = "/home/emulator/.aws/emulator/" + emulatorPort + "/"
	emulatorRegion  = "us-east-1"

	roleTrustPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"arn:aws:iam::000000000000:user/emulator"},"Action":"sts:AssumeRole"}]}`
	roleKMSPolicyFormat = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["kms:Encrypt","kms:Decrypt"],"Resource":%q}]}`
)

type awsEmulator struct {
	endpoint   string
	caPath     string
	httpClient *http.Client
	accessKey  string
	secretKey  string
}

func startAWSEmulator(t *testing.T) awsEmulator {
	t.Helper()
	ctx := t.Context()

	container, err := testcontainers.Run(
		ctx,
		"",
		testcontainers.WithDockerfile(testcontainers.FromDockerfile{
			Context:   "testdata/awsemulator",
			Repo:      "krypton-aws-emulator",
			Tag:       "test",
			KeepImage: true,
		}),
		testcontainers.WithCmd("-p", emulatorPort, "-t", "off"),
		testcontainers.WithExposedPorts(emulatorPort+"/tcp"),
		testcontainers.WithWaitStrategy(wait.ForLog("emulator server information")),
	)
	testcontainers.CleanupContainer(t, container)
	require.NoError(t, err)

	endpoint, err := container.PortEndpoint(ctx, emulatorPort+"/tcp", "https")
	require.NoError(t, err)

	ca := readContainerFile(t, container, "ca.pem")
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca))
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, ca, 0o600))

	accessKey, secretKey := parseCredentials(t, readContainerFile(t, container, "emulator_credentials"))

	return awsEmulator{
		endpoint: endpoint,
		caPath:   caPath,
		httpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}},
		accessKey: accessKey,
		secretKey: secretKey,
	}
}

func readContainerFile(t *testing.T, container testcontainers.Container, name string) []byte {
	t.Helper()
	r, err := container.CopyFileFromContainer(t.Context(), emulatorDataDir+name)
	require.NoError(t, err)
	defer r.Close()
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return b
}

func parseCredentials(t *testing.T, file []byte) (string, string) {
	t.Helper()
	values := map[string]string{}
	for line := range strings.Lines(string(file)) {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	require.NotEmpty(t, values["aws_access_key_id"])
	require.NotEmpty(t, values["aws_secret_access_key"])
	return values["aws_access_key_id"], values["aws_secret_access_key"]
}

func (e awsEmulator) config() aws.Config {
	return aws.Config{
		Region:       emulatorRegion,
		Credentials:  credentials.NewStaticCredentialsProvider(e.accessKey, e.secretKey, ""),
		BaseEndpoint: aws.String(e.endpoint),
		HTTPClient:   e.httpClient,
	}
}

func (e awsEmulator) kmsAdmin() *kms.Client {
	return kms.NewFromConfig(e.config())
}

func (e awsEmulator) createKey(t *testing.T) string {
	t.Helper()
	out, err := e.kmsAdmin().CreateKey(t.Context(), &kms.CreateKeyInput{})
	require.NoError(t, err)
	return *out.KeyMetadata.Arn
}

func (e awsEmulator) disableKey(t *testing.T, keyARN string) {
	t.Helper()
	_, err := e.kmsAdmin().DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: aws.String(keyARN)})
	require.NoError(t, err)
}

func (e awsEmulator) enableKey(t *testing.T, keyARN string) {
	t.Helper()
	_, err := e.kmsAdmin().EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: aws.String(keyARN)})
	require.NoError(t, err)
}

func (e awsEmulator) createRole(t *testing.T, keyARN string) string {
	t.Helper()
	ctx := t.Context()
	cli := iam.NewFromConfig(e.config())

	out, err := cli.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String("krypton-test"),
		AssumeRolePolicyDocument: aws.String(roleTrustPolicy),
	})
	require.NoError(t, err)

	_, err = cli.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       out.Role.RoleName,
		PolicyName:     aws.String("krypton-seal"),
		PolicyDocument: aws.String(fmt.Sprintf(roleKMSPolicyFormat, keyARN)),
	})
	require.NoError(t, err)
	return *out.Role.Arn
}

func (e awsEmulator) newSealer(t *testing.T, roleARN string) *Client {
	t.Helper()
	client, err := NewClient(
		Config{Region: emulatorRegion},
		Auth{
			RoleARN: roleARN,
			Static: &StaticCredentials{
				AccessKeyID:     e.accessKey,
				SecretAccessKey: e.secretKey,
			},
		},
		&Endpoint{KMSURL: e.endpoint, STSURL: e.endpoint, CAPath: e.caPath},
	)
	require.NoError(t, err)
	return client
}
