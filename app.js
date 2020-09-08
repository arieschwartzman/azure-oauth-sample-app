const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

const jwt = require('jsonwebtoken');
const session = require('express-session');
const KeyVaultSecret = require('@azure/keyvault-secrets');
const identity = require('@azure/identity');
const passport = require('passport');
const AzureAdOAuth2CertStrategy  = require("passport-azure-ad-oauth2-clientcert");
const assert = require('assert');
const graph = require('@microsoft/microsoft-graph-client');

require('isomorphic-fetch');
require('dotenv').config();

app.set('view engine', 'ejs');

app.use(session(
    {
        secret: '12345678'
    }));
    
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, cb) => cb(null, user));
passport.deserializeUser((obj, cb) => cb(null, obj));

app.get('/', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/azureadoauth2');
    }
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

const authOptions = {
    prompt: "select_account",
    state: undefined,
    scope: ['openid', 'profile', 'offline_access', 'User.Read']
};

async function initPassport(done) {
    console.log('Initializing Passport...');

    // Get PEM from KV using system managed identity
    const credentials = new identity.DefaultAzureCredential();
    assert(process.env.KEY_VAULT_URI,'KEY_VAULT_URI needs to be defined');
    assert(process.env.CLIENT_ID,'CLIENT_ID needs to be defined');
    assert(process.env.CLIENT_CERTIFICATE_NAME,'CLIENT_CERTIFICATE_NAME needs to be defined');

    const keyVaultClient = new KeyVaultSecret.SecretClient(process.env.KEY_VAULT_URI, credentials);
    console.log('Reading PEM from KeyVault...');
    const pem = await keyVaultClient.getSecret(process.env.CLIENT_CERTIFICATE_NAME);    

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
    done();
}
    
app.get('/auth/azureadoauth2',
    passport.authenticate('azure_ad_oauth2_clientcert', authOptions),
    function (req, res) {
        res.redirect('/');
    });

app.get('/auth/azureadoauth2/callback',
    passport.authenticate('azure_ad_oauth2_clientcert', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/');
    });

app.get('/logout', (req, res) => {
    req.logOut();
    return res.redirect('/');
});

initPassport(() => {
    console.log('Done Initializing passport')
    app.listen(port, async () => {
        console.log(`Example app listening at http://localhost:${port}`);
    });
});
