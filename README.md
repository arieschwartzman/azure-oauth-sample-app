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

## Read Certificate from Key Vault
``` javascript
const KeyVaultSecret = require('@azure/keyvault-secrets');
const identity = require('@azure/identity');

const credentials = new identity.DefaultAzureCredential();
const keyVaultClient = new KeyVaultSecret.SecretClient(process.env.KEY_VAULT_URI, credentials);
const pem = await keyVaultClient.getSecret(process.env.CLIENT_CERTIFICATE_NAME);    
```

## Passport strategy middleware setup

```javascript
const session = require('express-session');
const passport = require('passport');
const AzureAdOAuth2CertStrategy  = require("passport-azure-ad-oauth2-clientcert");

app.use(session(
    {
        secret: '12345678'
    }));
    
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, cb) => cb(null, user));
passport.deserializeUser((obj, cb) => cb(null, obj));

passport.use(new AzureAdOAuth2CertStrategy({
        authorizationURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenURL:'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        clientID: process.env.CLIENT_ID,
        callbackURL: process.env.REDIRECT_URI,
        pem: pem.value
    },
        function (accessToken, refresh_token, params, profile, done) {
            var decodedToken = jwt.decode(params.id_token);
            const userProfile = {
                displayName: decodedToken.name,
                emails: [{ value: decodedToken.preferred_username.toLowerCase() }],
                roles: decodedToken.roles,
                tenantID: decodedToken.tid,
                accessToken: accessToken
                
            };
            done(undefined, userProfile);
    }));    

```
## Authentication routes

```javascript
// main route is auth protected
app.get('/', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/azureadoauth2');
    }
    // Get profile from MS Graph API
    const client = graph.Client.init({authProvider: (done)=> {
        return done(undefined, req.user.accessToken);
    }});

    try {
        const me = await client.api('/me').get();
        return res.render('index', { me });
    }
    catch (err) {
        return res.render('error', { err });
    }
});

// Start authentication flow
app.get('/auth/azureadoauth2',
    passport.authenticate('azure_ad_oauth2_clientcert', authOptions),
    function (req, res) {
        res.redirect('/');
    });

// Handle redirect route
app.get('/auth/azureadoauth2/callback',
    passport.authenticate('azure_ad_oauth2_clientcert', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/');
    });

// Handle logout route
app.get('/logout', (req, res) => {
    req.logOut();
    return res.redirect('/');
});

```






