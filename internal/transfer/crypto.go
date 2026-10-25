package transfer

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// streamCipher 是传输内容的端到端加密（M10）：源端生成一次性密钥，
// 每块用 ChaCha20-Poly1305 密封（nonce = 7B 前缀 || 5B 块计数）。
// 中继/交换台只见密文；密钥经 controller 专递目的端（见 api.Keypass），
// 不进 grant（grant 头对中间节点可见）。manifest 签明文哈希，
// 落盘前全文件验证同时证明密钥正确。
type streamCipher struct {
	aead        cipher.AEAD
	noncePrefix []byte
}

func newStreamCipher() (*streamCipher, []byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	c, err := newStreamCipherFromKey(key)
	if err != nil {
		return nil, nil, err
	}
	return c, key, nil
}

func newStreamCipherFromKey(key []byte) (*streamCipher, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, 7)
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	return &streamCipher{aead: aead, noncePrefix: prefix}, nil
}

// material 返回给目的端的密钥材料（key || nonce 前缀）。
func (c *streamCipher) material() []byte {
	// 从 aead 无法取回 key——由发送侧在生成时单独传，见调用方。
	return c.noncePrefix
}

func (c *streamCipher) nonce(idx int64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	copy(n, c.noncePrefix)
	for i := 0; i < 5; i++ {
		n[11-i] = byte(idx >> (8 * i))
	}
	return n
}

func (c *streamCipher) seal(idx int64, pt []byte) []byte {
	return c.aead.Seal(nil, c.nonce(idx), pt, nil)
}

func (c *streamCipher) open(idx int64, ct []byte) ([]byte, error) {
	return c.aead.Open(nil, c.nonce(idx), ct, nil)
}

// —— 注入点：密钥的专递与获取（agent 连 controller 实现）——

var keyDeliverer func(grantID string, material []byte) error

// SetKeyDeliverer 注入密钥上报（源端，发送前调用）。
func SetKeyDeliverer(f func(grantID string, material []byte) error) { keyDeliverer = f }

var keyFetcher func(grantID string) ([]byte, error)

// SetKeyFetcher 注入密钥获取（目的端，接收时调用）。
func SetKeyFetcher(f func(grantID string) ([]byte, error)) { keyFetcher = f }

// cipherForGrant 组装本次传输的解密器（目的端）。
func cipherForGrant(grantID string) (*streamCipher, error) {
	if keyFetcher == nil {
		return nil, fmt.Errorf("未配置密钥获取")
	}
	mat, err := keyFetcher(grantID)
	if err != nil {
		return nil, err
	}
	if len(mat) != chacha20poly1305.KeySize+7 {
		return nil, fmt.Errorf("密钥材料长度异常")
	}
	aead, err := chacha20poly1305.New(mat[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, err
	}
	return &streamCipher{aead: aead, noncePrefix: mat[chacha20poly1305.KeySize:]}, nil
}
