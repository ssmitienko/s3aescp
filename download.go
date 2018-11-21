package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"crypto/aes"
	"crypto/cipher"

	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func DownloadAndDecrypt(source string, dest string, block cipher.Block, verbose bool, chunkSize int64, configuration Configuration) int {

	if verbose {
		log.Println("Downloading ", source, " to ", dest)
	}

	u, err := url.Parse(source)
	CheckErrorAndExit("Failed to parse source", err)

	if verbose {
		log.Println("scheme ", u.Scheme, " backet ", u.Host, " path ", u.Path)
	}

	creds := credentials.NewStaticCredentials(configuration.AwsAccessKeyID, configuration.AwsSecretAccessKey, "")
	_, err = creds.Get()
	CheckErrorAndExit("Bad AWS credentials", err)

	cfg := aws.NewConfig().WithRegion(configuration.AwsBucketRegion).WithCredentials(creds)
	svc := s3.New(session.New(), cfg)

	fileOut, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE, 0666)
	CheckErrorAndExit("Failed to open file", err)

	defer fileOut.Close()

	/*
		first do HEAD to get file size
	*/

	head := &s3.HeadObjectInput{
		Bucket: &u.Host,
		Key:    &u.Path,
	}

	result, err := svc.HeadObject(head)
	CheckErrorAndExit("S3 query result", err)

	if verbose {
		log.Printf("File size is %v", *result.ContentLength)
	}

	if *result.ContentLength < aes.BlockSize {
		CheckErrorAndExit("Operation failed", errors.New("Object is too small for an encrypted file"))
	}

	ivinput := &s3.GetObjectInput{
		Bucket: &u.Host,
		Key:    &u.Path,
		Range:  aws.String("bytes=0-15"),
	}

	ivresult, err := svc.GetObject(ivinput)
	CheckErrorAndExit("S3 query result", err)

	iv := make([]byte, aes.BlockSize)

	rc, err := ivresult.Body.Read(iv)
	//CheckErrorAndExit("S3 query result", err)

	if rc != aes.BlockSize {
		CheckErrorAndExit("Failed to read IV", errors.New("Incomplete read"))
	}

	stream := cipher.NewCTR(block, iv)

	plaintext := make([]byte, chunkSize)
	ciphertext := make([]byte, chunkSize)

	remain := *result.ContentLength - 16
	blockNum := 0

	var offset int64 = 16

	for remain > 0 {

		currentBlock := chunkSize
		if currentBlock > remain {
			currentBlock = remain
		}

		frange := fmt.Sprintf("bytes=%d-%d", offset, offset+currentBlock-1)

		if verbose {
			log.Println("Processing block:", blockNum, ", remaining bytes:", remain, ", range: ", frange)
		}

		input := &s3.GetObjectInput{
			Bucket: &u.Host,
			Key:    &u.Path,
			Range:  aws.String(frange),
		}

		res, err := svc.GetObject(input)
		CheckErrorAndExit("S3 GetObject result", err)

		currentBuffer := currentBlock

		for currentBuffer > 0 {
			rc, _ = res.Body.Read(ciphertext)
			//CheckErrorAndExit("S3 query result", err)

			stream.XORKeyStream(plaintext[:rc], ciphertext[:rc])

			w, err := fileOut.Write(plaintext[:rc])
			CheckErrorAndExit("Can't write destination file", err)

			if w != rc {
				CheckErrorAndExit("Failed to write output file", errors.New("Incomplete write"))
			}
			currentBuffer -= int64(rc)
		}

		blockNum++
		remain -= currentBlock
		offset += currentBlock
	}

	return 0
}
