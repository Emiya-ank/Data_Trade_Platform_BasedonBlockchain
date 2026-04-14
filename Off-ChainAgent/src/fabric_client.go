package offchain

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// FabricConfig 定义链码调用所需的网关配置。
type FabricConfig struct {
	MSPID             string
	PeerEndpoint      string // 例如 localhost:7051
	GatewayPeer       string // TLS SNI 名称，例如 peer0.org1.example.com
	TLSCertPath       string // peer tls ca 证书路径
	CertPath          string // user signcert 文件路径或目录
	KeyPath           string // user keystore 私钥文件路径或目录
	ChannelName       string
	ChaincodeName     string
	EvaluateTimeout   time.Duration
	EndorseTimeout    time.Duration
	SubmitTimeout     time.Duration
	CommitStatusDelay time.Duration
}

// FabricTrade 映射链上 Trade 结构，便于客户端反序列化。
type FabricTrade struct {
	ID         string `json:"id"`
	Buyer      string `json:"buyer"`
	Seller     string `json:"seller"`
	Key        string `json:"key"`
	Hash       string `json:"hash"`
	Status     string `json:"status"`
	Amount     int64  `json:"amount"`
	Timeout    int64  `json:"timeout"`
	CreateTime int64  `json:"createTime"`
	EndTime    int64  `json:"endTime"`
}

// FabricClient 封装 Fabric Gateway 合约调用。
type FabricClient struct {
	conn     *grpc.ClientConn
	gateway  *client.Gateway
	network  *client.Network
	contract *client.Contract
}

// NewFabricClient 创建一个新的 FabricClient 实例，连接到指定的 Fabric 网络和链码。
func NewFabricClient(cfg FabricConfig) (*FabricClient, error) {
	if cfg.MSPID == "" || cfg.PeerEndpoint == "" || cfg.GatewayPeer == "" || cfg.TLSCertPath == "" {
		return nil, fmt.Errorf("fabric config missing required fields (mspid/peer endpoint/gateway peer/tls cert)")
	}
	if cfg.ChannelName == "" || cfg.ChaincodeName == "" {
		return nil, fmt.Errorf("fabric config missing required fields (channel name/chaincode name)")
	}

	if cfg.EvaluateTimeout <= 0 {
		cfg.EvaluateTimeout = 5 * time.Second
	}
	if cfg.EndorseTimeout <= 0 {
		cfg.EndorseTimeout = 15 * time.Second
	}
	if cfg.SubmitTimeout <= 0 {
		cfg.SubmitTimeout = 5 * time.Second
	}
	if cfg.CommitStatusDelay <= 0 {
		cfg.CommitStatusDelay = 60 * time.Second
	}

	conn, err := newGRPCConnection(cfg.PeerEndpoint, cfg.GatewayPeer, cfg.TLSCertPath)
	if err != nil {
		return nil, err
	}

	id, err := newIdentity(cfg.MSPID, cfg.CertPath)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sign, err := newSign(cfg.KeyPath)
	if err != nil {
		conn.Close()
		return nil, err
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(cfg.EvaluateTimeout),
		client.WithEndorseTimeout(cfg.EndorseTimeout),
		client.WithSubmitTimeout(cfg.SubmitTimeout),
		client.WithCommitStatusTimeout(cfg.CommitStatusDelay),
	)
	if err != nil {
		conn.Close()
		return nil, err
	}

	network := gw.GetNetwork(cfg.ChannelName)
	contract := network.GetContract(cfg.ChaincodeName)

	return &FabricClient{
		conn:     conn,
		gateway:  gw,
		network:  network,
		contract: contract,
	}, nil
}

// Close 关闭 FabricClient，释放底层连接资源。
func (c *FabricClient) Close() error {
	if c == nil {
		return nil
	}
	if c.gateway != nil {
		c.gateway.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// 以下是链码函数的封装，调用时传入相应参数即可。
func (c *FabricClient) CreateTrade(id string, seller string, timeoutSeconds int64, hash string) error {
	_, err := c.contract.SubmitTransaction(
		"CreateTrade",
		id,
		seller,
		strconv.FormatInt(timeoutSeconds, 10),
		hash,
	)
	return err
}

// InitBalance 初始化当前调用者链上余额。
func (c *FabricClient) InitBalance(amount int64) error {
	_, err := c.contract.SubmitTransaction("InitBalance", strconv.FormatInt(amount, 10))
	return err
}

// LockTrade 会将指定金额锁定在链码中，等待后续的提交密钥和验证操作。
func (c *FabricClient) LockTrade(id string, amount int64) error {
	_, err := c.contract.SubmitTransaction("LockTrade", id, strconv.FormatInt(amount, 10))
	return err
}

// SubmitKeyAndVerify 提交密钥并触发链码中的验证逻辑，链码会根据预设的验证结果更新交易状态。
func (c *FabricClient) SubmitKeyAndVerify(id string, key string) error {
	_, err := c.contract.SubmitTransaction("SubmitKeyandVerify", id, key)
	return err
}

// RefundTrade 在交易超时或验证失败的情况下调用，链码会将锁定的金额退回给买家，并更新交易状态。
func (c *FabricClient) RefundTrade(id string) error {
	_, err := c.contract.SubmitTransaction("RefundTrade", id)
	return err
}

// GetTrade 查询链码中指定 ID 的交易详情，返回一个 FabricTrade 结构体，包含交易的各项信息。
func (c *FabricClient) GetTrade(id string) (*FabricTrade, error) {
	raw, err := c.contract.EvaluateTransaction("GetTrade", id)
	if err != nil {
		return nil, err
	}
	var t FabricTrade
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// QueryEscrow 查询链码中指定 ID 的交易的锁定金额，返回一个整数表示当前锁定的金额数值。
func (c *FabricClient) QueryEscrow(id string) (int64, error) {
	raw, err := c.contract.EvaluateTransaction("QueryEscrow", id)
	if err != nil {
		return 0, err
	}
	return parseInt64Bytes(raw)
}

// QueryBalance 查询链码中指定 clientID 的账户余额，返回一个整数表示当前余额数值。
func (c *FabricClient) QueryBalance(clientID string) (int64, error) {
	raw, err := c.contract.EvaluateTransaction("QueryBalance", clientID)
	if err != nil {
		return 0, err
	}
	return parseInt64Bytes(raw)
}


func newGRPCConnection(peerEndpoint string, gatewayPeer string, tlsCertPath string) (*grpc.ClientConn, error) {
	certificatePEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("read tls cert failed: %w", err)
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		return nil, fmt.Errorf("parse tls cert failed: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("create grpc connection failed: %w", err)
	}
	return connection, nil
}

func newIdentity(mspID string, certPath string) (*identity.X509Identity, error) {
	resolvedPath, err := resolveSingleFilePath(certPath)
	if err != nil {
		return nil, err
	}

	certificatePEM, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("read cert file failed: %w", err)
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		return nil, fmt.Errorf("parse cert file failed: %w", err)
	}
	return identity.NewX509Identity(mspID, certificate)
}

func newSign(keyPath string) (identity.Sign, error) {
	resolvedPath, err := resolveSingleFilePath(keyPath)
	if err != nil {
		return nil, err
	}

	privateKeyPEM, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("read key file failed: %w", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key failed: %w", err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create sign function failed: %w", err)
	}
	return sign, nil
}

// resolveSingleFilePath 支持传入“文件路径”或“目录路径（自动取第一个文件）”。
func resolveSingleFilePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("empty path")
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return path, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, filepath.Join(path, e.Name()))
	}
	sort.Strings(files)
	if len(files) == 0 {
		return "", fmt.Errorf("no files found in directory: %s", path)
	}
	return files[0], nil
}

func parseInt64Bytes(raw []byte) (int64, error) {
	text := strings.TrimSpace(string(raw))
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse int64 failed from %q: %w", text, err)
	}
	return v, nil
}
