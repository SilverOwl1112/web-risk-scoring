#!/bin/bash
# Initialize and deploy Elastic Beanstalk environment for Flask backend

APP_NAME="web-risk-scoring"
ENV_NAME="web-risk-scoring-env"
REGION="us-east-1"

cd ../backend

# Initialize EB (Docker platform)
eb init "$APP_NAME" --platform docker --region "$REGION"

# Create environment if it doesn't exist
if ! eb list | grep -q "$ENV_NAME"; then
  eb create "$ENV_NAME"
fi

# Deploy the app
eb deploy "$ENV_NAME"

echo "✅ Deployment complete! Visit your app via Elastic Beanstalk console."
