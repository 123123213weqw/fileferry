package transfer

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
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

// cipherFromMaterial 用现成密钥材料（key || prefix）组装 cipher——
// 目的端解密与源端目录模式派生共用。prefix 不再重新随机：nonce 必须与
// 对端一致，且同一 grant 内所有文件共用同一前缀（密钥不同即安全）。
func cipherFromMaterial(key, prefix []byte) (*streamCipher, error) {
	if len(key) != chacha20poly1305.KeySize || len(prefix) != 7 {
		return nil, fmt.Errorf("密钥材料长度异常")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &streamCipher{aead: aead, noncePrefix: append([]byte(nil), prefix...)}, nil
}

// DeriveFileKey 从 grant 主密钥为目录内每个文件派生独立密钥
//（HKDF-SHA256，info 绑定相对路径）。目录模式下多文件共用同一
// chunk 索引空间（每文件都从块 0 开始），若共用密钥则跨文件 nonce
// 重用——AEAD 的致命错误。派生后每文件密钥互异，nonce 只在单文件
// 内使用，安全性恢复。
func DeriveFileKey(master []byte, relPath string) []byte {
	r := hkdf.New(sha256.New, master, nil, []byte("fileferry/dir-file/"+relPath))
	out := make([]byte, chacha20poly1305.KeySize)
	io.ReadFull(r, out) // SHA-256 读源不会出错
	return out
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

// cipherForGrant 组装本次传输的解密器（目的端）。relPath 非空
//（目录模式）时按 HKDF(主钥, 相对路径) 派生文件密钥——与发送端
// SendTree 的派生严格对称；空 = 单文件模式直接用主钥。
func cipherForGrant(grantID, relPath string) (*streamCipher, error) {
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
	key := mat[:chacha20poly1305.KeySize]
	prefix := mat[chacha20poly1305.KeySize:]
	if relPath != "" {
		key = DeriveFileKey(key, relPath)
	}
	return cipherFromMaterial(key, prefix)
}
