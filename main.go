package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	excludeFiles = map[string]struct{}{
		"main.go":    struct{}{},
		"encrypt.go": struct{}{},
		"decrypt.go": struct{}{},
		"key.txt":    struct{}{},
		"main.exe":    struct{}{}, // Exclude the key file
	}
	keyFile = "key.txt"
)

func shouldExclude(fileName string) bool {
	_, excluded := excludeFiles[fileName]
	return excluded
}

func generateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func saveKeyToFile(key []byte) error {
	return ioutil.WriteFile(keyFile, key, 0644)
}

func loadKeyFromFile() ([]byte, error) {
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encrypt(text string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(ciphertextBytes, ciphertextBytes)

	return string(ciphertextBytes), nil
}

func listAndEncrypt(rootDir string, key []byte) error {
	return filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Exclude directories (including the root directory itself)
		if info.IsDir() {
			return nil
		}

		// Exclude specified files
		if shouldExclude(info.Name()) {
			return nil
		}

		// Read the file content
		content, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", path, err)
			return nil
		}

		// Encrypt the content
		encryptedContent, err := encrypt(string(content), key)
		if err != nil {
			fmt.Printf("Error encrypting %s: %v\n", path, err)
			return nil
		}

		// Overwrite the existing file with the encrypted content
		err = ioutil.WriteFile(path, []byte(encryptedContent), 0644)
		if err != nil {
			fmt.Printf("Error overwriting %s with encrypted content: %v\n", path, err)
			return nil
		}

		// Print the encrypted file path
		fmt.Println("Encrypted", path)

		return nil
	})
}

func listAndDecrypt(rootDir string, key []byte) error {
	return filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Exclude directories (including the root directory itself)
		if info.IsDir() {
			return nil
		}

		// Exclude specified files
		if shouldExclude(info.Name()) {
			return nil
		}

		// Read the encrypted file content
		content, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", path, err)
			return nil
		}

		// Decrypt the content
		decryptedContent, err := decrypt(string(content), key)
		if err != nil {
			fmt.Printf("Error decrypting %s: %v\n", path, err)
			return nil
		}

		// Overwrite the existing file with the decrypted content
		err = ioutil.WriteFile(path, []byte(decryptedContent), 0644)
		if err != nil {
			fmt.Printf("Error overwriting %s with decrypted content: %v\n", path, err)
			return nil
		}

		// Print the decrypted file path
		fmt.Println("Decrypted", path)

		return nil
	})
}

func main() {
	fmt.Println("Choose an action:")
	fmt.Println("1. Encrypt and save key")
	fmt.Println("2. Decrypt")

	var action int
	fmt.Scan(&action)

	switch action {
	case 1:
		// Encryption
		rootDir := "." // You can change this to the desired directory

		key, err := generateKey()
		if err != nil {
			fmt.Println("Error generating key:", err)
			return
		}

		err = saveKeyToFile(key)
		if err != nil {
			fmt.Println("Error saving key to file:", err)
			return
		}

		err = listAndEncrypt(rootDir, key)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		// Print the key for reference (you may want to remove this in a production scenario)
		fmt.Println("Key:", hex.EncodeToString(key))

		fmt.Println("Encryption and key saving complete.")
	case 2:
		// Decryption
		key, err := loadKeyFromFile()
		if err != nil {
			fmt.Println("Key not found. Please run encryption first.")
			return
		}

		rootDir := "." // You can change this to the desired directory
		err = listAndDecrypt(rootDir, key)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		// Remove the key file after decryption
		err = os.Remove(keyFile)
		if err != nil {
			fmt.Println("Error removing key file:", err)
		}

		fmt.Println("Decryption complete.")
	default:
		fmt.Println("Invalid action. Choose 1 or 2.")
	}
}
