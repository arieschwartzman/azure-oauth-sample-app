# azure-oauth-sample-app

- Node.js/Express application that demonstrates federated authentication using AAD Application with Client Certificate stored in [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/general/overview) and accessed by a App Service using a [System Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).

- [Passport strategy](https://www.npmjs.com/package/passport-azure-ad-oauth2-clientcert) package is used to simplify the authentication flow with the support for client certificate


## Running locally
1. Clone this repo
2. npm install
2. Create Key Vault resource and generate a certificate as described in this [blog post](https://nirvana.schwartzman.info/wordpress/2020/09/05/authenticate-using-client-certificate-and-system-managed-identity/)
3. Register AAD Application and upload the public key as the authentication key
4. Configure the .env file with the following values

```JSON
KEY_VAULT_URI=https://<key vault name>.vault.azure.net/
CLIENT_ID=<App registration client Id>
REDIRECT_URI=http://localhost:3000/auth/azureadoauth2/callback
CLIENT_CERTIFICATE_NAME=<cert-secret-name>
```
5. Run the application









