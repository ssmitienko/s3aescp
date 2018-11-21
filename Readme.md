# s3aescp 

Copy files to or from AWS S3 with client-side AES encryption. 
This program can be used as a replacement for s3cmd in your backup scripts.
All encryption is done in-flight.

## Getting Started

To build you'll need a Go compiler and AWS Go SDK modules.

```
go get github.com/aws/aws-sdk-go/aws
go get github.com/aws/aws-sdk-go/aws/awserr
go get github.com/aws/aws-sdk-go/aws/credentials
go get github.com/aws/aws-sdk-go/aws/session
go get github.com/aws/aws-sdk-go/service/s3
go build
```

## Usage examples

Upload to S3:

s3aescp -config /etc/s3aescp.json mybackup.zip s3://my.backup.backet/mybackup.zip.aes 

Download from S3:

s3aescp -config /etc/s3aescp.json s3://my.backup.backet/mybackup.zip.aes mybackup.zip

Localy encrypt file:

s3aescp -config /etc/s3aescp.json -encrypt mybackup.zip mybackup.zip.aes

Localy decrypt file:

s3aescp -config /etc/s3aescp.json -encrypt mybackup.zip.aes mybackup.zip

## Config file format

{
     "AwsAccessKeyID": "YourAwsKeyID",
     "AwsSecretAccessKey": "YourAWSSecret",
     "AwsBucketRegion": "eu-central-1",
     "AesKey": "00112233445566778899aabbccddeeff"
}

AES key is 128 bit in hexadecimal format.

## .aes file format

First 16 bytes are random IV, the rest is original file encrypted in AES-CTR
mode.

## TODO

Parallel upload and download.
