# Login to your account
gcloud auth login

# Check which account is currently active
gcloud auth list

# Switch to a Different Account
gcloud config set account ACCOUNT_EMAIL

# Set a Default Project for the Account
gcloud config set project PROJECT_ID

# Install the Google Cloud SDK
curl https://sdk.cloud.google.com | bash
gcloud init

# Create a service account
gcloud iam service-accounts create infrastructure-manager

# Grant necessary permissions
gcloud projects add-iam-policy-binding your-project-id \
    --member="serviceAccount:infrastructure-manager@your-project-id.iam.gserviceaccount.com" \
    --role="roles/compute.admin"

# Create and download credentials file
gcloud iam service-accounts keys create credentials.json \
    --iam-account=infrastructure-manager@your-project-id.iam.gserviceaccount.com


# Create the env
python gcp_infrastructure.py

# Destroy the env
python gcp_infrastructure.py destroy