#!/bin/bash
# Create S3 bucket (run only once)
REGION="us-east-1"
BUCKET_NAME="web-risk-scoring-bucket"

aws s3 mb s3://$BUCKET_NAME --region $REGION
aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private
echo "✅ Bucket $BUCKET_NAME created in $REGION"
