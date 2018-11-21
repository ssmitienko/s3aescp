package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"encoding/hex"
	"encoding/json"
)

type Configuration struct {
	AwsAccessKeyID     string
	AwsSecretAccessKey string
	AwsBucketRegion    string
	AesKey             string
}

func CheckErrorAndExit(message string, err error) {

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", message, err)
		os.Exit(1)
	}
}

func LocalEncryptDecrypt(source string, dest string, block cipher.Block, verbose bool, chunkSize int64, encryptFlag bool) int {

	fileIn, err := os.OpenFile(source, os.O_RDONLY, 0666)
	CheckErrorAndExit("Failed to open file", err)

	defer fileIn.Close()

	statIn, err := os.Stat(source)
	CheckErrorAndExit("Failed to read file info", err)

	fileOut, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE, 0666)
	CheckErrorAndExit("Failed to open file", err)

	defer fileOut.Close()

	/*
		RandomIV for CTR mode
	*/

	iv := make([]byte, aes.BlockSize)

	if encryptFlag {

		/*
			Encrypt - get random IV and write it as first bytes to output file
		*/

		_, err := io.ReadFull(rand.Reader, iv)
		CheckErrorAndExit("Can't get random data for AES IV", err)

		/*
			Write IV
		*/

		_, err = fileOut.Write(iv)
		CheckErrorAndExit("Can't write IV to output file", err)
	} else {

		/*
			Decrypt - get IV from input file
		*/

		r, err := fileIn.Read(iv)
		CheckErrorAndExit("Can't read IV from input file", err)

		if r != aes.BlockSize {
			CheckErrorAndExit("Failed to read IV from input file", errors.New("Incomplete read"))
		}
	}

	stream := cipher.NewCTR(block, iv)

	plaintext := make([]byte, chunkSize)
	ciphertext := make([]byte, chunkSize)

	remain := statIn.Size()

	/*
		Skip IV then decrypting
	*/

	if encryptFlag == false {
		remain -= aes.BlockSize
	}

	blockNum := 0

	for remain > 0 {

		if verbose {
			log.Println("Processing block:", blockNum, ", remaining bytes:", remain)
		}

		currentBlock := chunkSize
		if currentBlock > remain {
			currentBlock = remain
		}

		r, err := fileIn.Read(plaintext)
		CheckErrorAndExit("Can't read source file", err)

		if r != int(currentBlock) {
			CheckErrorAndExit("Failed to read input file", errors.New("Incomplete read"))
		}

		stream.XORKeyStream(ciphertext, plaintext[:currentBlock])

		w, err := fileOut.Write(ciphertext[:currentBlock])
		CheckErrorAndExit("Can't write destination file", err)

		if w != int(currentBlock) {
			CheckErrorAndExit("Failed to write output file", errors.New("Incomplete write"))
		}

		blockNum++
		remain -= currentBlock
	}
	return 0
}

func main() {

	configuration := Configuration{}

	cfgNamePtr := flag.String("config", "./s3aescp.json", "config file name with AWS credentials and AES key")
	verbPtr := flag.Bool("verbose", false, "verbose output")
	encrPtr := flag.Bool("encrypt", false, "encrypt file localy")
	decrPtr := flag.Bool("decrypt", false, "decrypt file localy")
	chunkPtr := flag.Int64("chunk", 5*1024, "chunk size in kilobytes")

	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	if len(flag.Args()) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	if *chunkPtr < 0 {
		fmt.Fprintf(os.Stderr, "Invalid chunk size\n")
		os.Exit(1)
	}

	if *encrPtr && *decrPtr {
		fmt.Fprintf(os.Stderr, "Cannot to encryption and decryption at the same time\n")
		os.Exit(1)
	}

	if *verbPtr {
		log.Println("cfgName:", *cfgNamePtr)
	}

	file, err := os.Open(*cfgNamePtr)
	CheckErrorAndExit("Failed to read configuration", err)

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&configuration)
	CheckErrorAndExit("Failed to parse configuration", err)
	file.Close()

	if *verbPtr {
		log.Println("AwsAccessKeyID:", configuration.AwsAccessKeyID)
		log.Println("AwsSecretAccessKey:", "********")
		log.Println("AwsBucketRegion:", configuration.AwsBucketRegion)
		log.Println("AesKey:", "********")
	}

	if len(configuration.AesKey) != 32 {
		CheckErrorAndExit("Failed to parse configuration", errors.New("Invalid AES key"))
	}

	key, err := hex.DecodeString(configuration.AesKey)
	CheckErrorAndExit("Failed to decode AES key", err)

	block, err := aes.NewCipher(key)
	CheckErrorAndExit("Failed to initialise AES cipher", err)

	if *encrPtr {
		os.Exit(LocalEncryptDecrypt(flag.Args()[0], flag.Args()[1], block, *verbPtr, *chunkPtr*1024, true))
	}

	if *decrPtr {
		os.Exit(LocalEncryptDecrypt(flag.Args()[0], flag.Args()[1], block, *verbPtr, *chunkPtr*1024, false))
	}

	if strings.HasPrefix(flag.Args()[0], "s3://") {
		if strings.HasPrefix(flag.Args()[1], "s3://") {
			fmt.Fprintf(os.Stderr, "Copying files from s3 to s3 not supported\n")
			os.Exit(1)
		}
		os.Exit(DownloadAndDecrypt(flag.Args()[0], flag.Args()[1], block, *verbPtr, *chunkPtr*1024, configuration))
	}

	if strings.HasPrefix(flag.Args()[1], "s3://") {
		os.Exit(UploadAndEncrypt(flag.Args()[0], flag.Args()[1], block, *verbPtr, *chunkPtr*1024, configuration))
	}

	fmt.Fprintf(os.Stderr, "For local operations please specify encryption or decryption flag\n")
	flag.Usage()
	os.Exit(1)
}
