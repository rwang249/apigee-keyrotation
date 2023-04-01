# apigee-keyrotation

## Description
The code in this repo is sample code used to demonstrate key rotation against Apigee using a Go Function App. The code does the following:

1. Connect to Azure Key Vault to get TLS certificates for Vault authentication
2. Access Vault to get json service account key for Apigee
3. Generate JWT
4. Use JWT token to authenticate with Google to get OAuth2 token
5. Utilize OAuth2 token to access Apigee APIs to get applications
6. For each app, generate a random string using the Hashicorp Vault random function
7. Update key for app
8. Gather list of products associated with app and update each association with the new key + approve products

Authentication to Google was done manually using JWT and OAuth2 tokens. Secrets stored in files are deleted at the end of each utilizing function, and if not done is deleted as the function app does not persist post code execution.
