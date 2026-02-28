package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

//加密过程：
//  1、处理数据，对数据进行填充，采用PKCS7（当密钥长度不够时，缺几位补几个几）的方式。
//  2、对数据进行加密，采用AES加密方法中CBC加密模式，使用随机IV
//  3、对得到的加密数据（IV前缀+密文），进行base64加密，得到字符串
// 解密过程相反

// pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7UnPadding 填充的反向操作
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	if unPadding > length {
		return nil, errors.New("填充长度错误")
	}
	if unPadding == 0 {
		return nil, errors.New("填充长度不能为0")
	}
	// 验证填充是否合法
	for i := length - unPadding; i < length; i++ {
		if data[i] != byte(unPadding) {
			return nil, errors.New("非法的PKCS7填充")
		}
	}
	return data[:(length - unPadding)], nil
}

// AesEncrypt 加密（接受显式IV参数）
func AesEncrypt(data []byte, key []byte, iv []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密块的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, iv)
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

// AesDecrypt 解密（接受显式IV参数）
func AesDecrypt(data []byte, key []byte, iv []byte) ([]byte, error) {
	//创建实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(block, iv)
	//初始化解密数据接收切片
	crypted := make([]byte, len(data))
	//执行解密
	blockMode.CryptBlocks(crypted, data)
	//去除填充
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

// EncryptByAes Aes加密：生成随机IV，将IV前缀附加到密文，再进行base64编码
func EncryptByAes(data []byte) (string, error) {
	PwdKey := getSecretKey()

	// 生成随机IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		return "", fmt.Errorf("生成随机IV失败: %w", err)
	}

	res, err := AesEncrypt(data, PwdKey, iv)
	if err != nil {
		return "", err
	}
	// 将IV前缀附加到密文中
	result := append(iv, res...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptByAes Aes解密：从密文中提取IV前缀，再解密
func DecryptByAes(data string) ([]byte, error) {
	if data == "" {
		return nil, errors.New("加密数据不能为空")
	}

	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.New("base64解码失败：" + err.Error())
	}

	// 数据必须至少包含一个IV块（16字节）加至少一个密文块（16字节）
	if len(dataByte) < 2*aes.BlockSize || len(dataByte[aes.BlockSize:])%aes.BlockSize != 0 {
		return nil, errors.New("无效的加密数据长度")
	}

	// 提取IV和密文
	iv := dataByte[:aes.BlockSize]
	ciphertext := dataByte[aes.BlockSize:]

	PwdKey := getSecretKey()
	return AesDecrypt(ciphertext, PwdKey, iv)
}

var (
	secretKey     []byte
	secretKeyOnce sync.Once
)

// getSecretKey 获取AES密钥（懒加载单例）
func getSecretKey() []byte {
	secretKeyOnce.Do(func() {
		secretKey = loadOrCreateSecretKey()
	})
	return secretKey
}

// loadOrCreateSecretKey 从文件加载或生成并持久化一个随机的32字节密钥
func loadOrCreateSecretKey() []byte {
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("[安全警告] 无法获取可执行文件路径，使用弱密钥: %v", err)
		return generateFallbackKey()
	}

	secretPath := filepath.Join(filepath.Dir(execPath), "data", ".secret")

	// 尝试加载已有密钥
	data, err := os.ReadFile(secretPath)
	if err == nil && len(data) == 32 {
		return data
	}

	// 生成新随机密钥
	key := make([]byte, 32)
	if _, err := io.ReadFull(crand.Reader, key); err != nil {
		log.Printf("[安全警告] 随机密钥生成失败，使用弱密钥: %v", err)
		return generateFallbackKey()
	}

	// 持久化密钥
	if err := os.MkdirAll(filepath.Dir(secretPath), 0700); err != nil {
		log.Printf("[安全警告] 密钥目录创建失败，重启后密钥将重置: %v", err)
	} else if err := os.WriteFile(secretPath, key, 0600); err != nil {
		log.Printf("[安全警告] 密钥持久化失败，重启后密钥将重置: %v", err)
	}

	return key
}

// generateFallbackKey 当随机密钥生成失败时，基于可执行文件路径生成密钥（兜底方案）
func generateFallbackKey() []byte {
	str, _ := os.Executable()
	key := make([]byte, 0, 32)
	if len(str) > 32 {
		key = append(key, str[:32]...)
	} else {
		key = append(key, str...)
		remain := 32 - len(str)
		for i := 0; i < remain; i++ {
			key = append(key, 'A')
		}
	}
	return key
}
