package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const (
	maxRetries = 10
)

func UploadAndEncrypt(source string, dest string, block cipher.Block, verbose bool, chunkSize int64, configuration Configuration) int {

	if verbose {
		log.Println("Uploading ", source, " to ", dest)
	}

	fileIn, err := os.Open(source)

	CheckErrorAndExit("Failed to open file", err)

	defer fileIn.Close()

	statIn, err := os.Stat(source)
	CheckErrorAndExit("Failed to read file info", err)

	/*
		Generate IV
	*/

	iv := make([]byte, aes.BlockSize)

	_, err = io.ReadFull(rand.Reader, iv)
	CheckErrorAndExit("Can't get random data for AES IV", err)

	/*
		Parse S3 URL
	*/

	u, err := url.Parse(dest)
	CheckErrorAndExit("Failed to parse destination", err)

	if verbose {
		log.Println("Source file size: ", statIn.Size())
		log.Println("scheme ", u.Scheme, " backet ", u.Host, " path ", u.Path)
	}

	creds := credentials.NewStaticCredentials(configuration.AwsAccessKeyID, configuration.AwsSecretAccessKey, "")
	_, err = creds.Get()
	CheckErrorAndExit("Bad AWS credentials", err)

	cfg := aws.NewConfig().WithRegion(configuration.AwsBucketRegion).WithCredentials(creds)
	svc := s3.New(session.New(), cfg)

	ctype := "binary/octet-stream"

	stream := cipher.NewCTR(block, iv)

	plaintext := make([]byte, chunkSize)
	ciphertext := make([]byte, chunkSize)

	remain := statIn.Size() + 16

	/*
		One chunk upload is done via simple PUT request

	*/

	if remain <= chunkSize {

		if verbose {
			log.Println("Doing simple 1-block upload, bytes:", remain)
		}

		r, err := fileIn.Read(plaintext[aes.BlockSize:])
		CheckErrorAndExit("Can't read source file", err)

		r += aes.BlockSize
		if r != int(remain) {
			CheckErrorAndExit("Failed to read input file", errors.New("Incomplete read"))
		}

		copy(ciphertext[0:aes.BlockSize], iv[:])
		stream.XORKeyStream(ciphertext[aes.BlockSize:r], plaintext[aes.BlockSize:r])

		// Upload input parameters
		input := &s3.PutObjectInput{
			Bucket:      &u.Host,
			Key:         &u.Path,
			ContentType: &ctype,
			Body:        bytes.NewReader(ciphertext[:r]),
		}

		result, err := svc.PutObject(input)
		CheckErrorAndExit("Failed to upload file", err)
		fmt.Printf("Successfully uploaded file: %s\n", result.String())

		return 0
	}

	/*
		Do nultipart upload
	*/

	input := &s3.CreateMultipartUploadInput{
		Bucket:      &u.Host,
		Key:         &u.Path,
		ContentType: &ctype,
	}

	resp, err := svc.CreateMultipartUpload(input)
	CheckErrorAndExit("Failed to create MultipartUpload request", err)

	var completedParts []*s3.CompletedPart

	blockNum := 1

	for remain > 0 {

		if verbose {
			log.Println("Processing block:", blockNum, ", remaining bytes:", remain)
		}

		currentBlock := chunkSize
		if currentBlock > remain {
			currentBlock = remain
		}

		/*
			Insert IV into first block
		*/

		var r int

		if blockNum == 1 {
			r, err = fileIn.Read(plaintext[aes.BlockSize:])
			r += aes.BlockSize

		} else {
			r, err = fileIn.Read(plaintext)
		}

		CheckErrorAndExit("Can't read source file", err)

		if r != int(currentBlock) {
			CheckErrorAndExit("Failed to read input file", errors.New("Incomplete read"))
		}

		/*
			Do not encrypt IV in the first block
		*/

		if blockNum == 1 {
			copy(ciphertext[0:aes.BlockSize], iv[:])
			stream.XORKeyStream(ciphertext[aes.BlockSize:currentBlock], plaintext[aes.BlockSize:currentBlock])
		} else {
			stream.XORKeyStream(ciphertext, plaintext[:currentBlock])
		}

		completedPart, err := uploadPart(svc, resp, ciphertext[:currentBlock], blockNum)

		if err != nil {
			fmt.Fprintf(os.Stderr, "MultipartUpload failed: %v\n", err)
			err := abortMultipartUpload(svc, resp)
			CheckErrorAndExit("abortion of MultipartUpload failed", err)
			return 1
		}

		blockNum++
		remain -= currentBlock
		completedParts = append(completedParts, completedPart)
	}

	completeResponse, err := completeMultipartUpload(svc, resp, completedParts)
	CheckErrorAndExit("MultipartUpload failed", err)

	fmt.Printf("Successfully uploaded file: %s\n", completeResponse.String())
	return 0
}

/*
	Shameless copy from https://github.com/apoorvam/aws-s3-multipart-upload/blob/master/aws-multipart-upload.go
*/

func completeMultipartUpload(svc *s3.S3, resp *s3.CreateMultipartUploadOutput, completedParts []*s3.CompletedPart) (*s3.CompleteMultipartUploadOutput, error) {
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   resp.Bucket,
		Key:      resp.Key,
		UploadId: resp.UploadId,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}
	return svc.CompleteMultipartUpload(completeInput)
}

func uploadPart(svc *s3.S3, resp *s3.CreateMultipartUploadOutput, fileBytes []byte, partNumber int) (*s3.CompletedPart, error) {
	tryNum := 1
	partInput := &s3.UploadPartInput{
		Body:          bytes.NewReader(fileBytes),
		Bucket:        resp.Bucket,
		Key:           resp.Key,
		PartNumber:    aws.Int64(int64(partNumber)),
		UploadId:      resp.UploadId,
		ContentLength: aws.Int64(int64(len(fileBytes))),
	}

	for tryNum <= maxRetries {
		uploadResult, err := svc.UploadPart(partInput)
		if err != nil {
			if tryNum == maxRetries {
				if aerr, ok := err.(awserr.Error); ok {
					return nil, aerr
				}
				return nil, err
			}
			fmt.Printf("Retrying to upload part #%v\n", partNumber)
			tryNum++
		} else {
			fmt.Printf("Uploaded part #%v\n", partNumber)
			return &s3.CompletedPart{
				ETag:       uploadResult.ETag,
				PartNumber: aws.Int64(int64(partNumber)),
			}, nil
		}
	}
	return nil, nil
}

func abortMultipartUpload(svc *s3.S3, resp *s3.CreateMultipartUploadOutput) error {
	fmt.Println("Aborting multipart upload for UploadId#" + *resp.UploadId)
	abortInput := &s3.AbortMultipartUploadInput{
		Bucket:   resp.Bucket,
		Key:      resp.Key,
		UploadId: resp.UploadId,
	}
	_, err := svc.AbortMultipartUpload(abortInput)
	return err
}
