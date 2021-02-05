const AWS = require('aws-sdk')
const jsonwebtoken = require('jsonwebtoken')
const jwkToPem = require('jwk-to-pem')
const axios = require('axios')
const { ProcessCredentials } = require('aws-sdk')

const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
    credentials: {
        accessKeyId: process.env.ACCESS_KEY,
        secretAccessKey: process.env.SECRET_ACCESS_KEY,
    },
    region: 'eu-central-1'
})

// cognitoidentityserviceprovider.adminCreateUser({
//     UserPoolId: 'eu-central-1_5wvFbUNEg',
//     Username: 'test-ciao',
// }, function(err, data) {
//     console.log(err, data)
// })

const keysUrl = process.env.COGNITO_PUBLIC_KEY_URL

var params = {
    AuthFlow: 'ADMIN_USER_PASSWORD_AUTH', /* required */
    ClientId: process.env.COGNITO_CLIENT_ID, /* required */
    UserPoolId: process.env.COGNITO_USER_POOL_ID, /* required */
    AuthParameters: null
}

const users = [
    {
        "USERNAME": "bellomimarc",
        "PASSWORD": "marcello"
    },
    {
        "USERNAME": "marco",
        "PASSWORD": "marcomarco",
    },
]

const performAdminAuth = (params, pems) => {
    /**
     * For this to work we must create an appclient without secret
     * There is a cli function for this:
     * aws cognito-idp create-user-pool-client \
     * --no-generate-secret \
     * --user-pool-id eu-central-1_5wvFbUNEg \
     * --client-name backend-auth \
     {
                "UserPoolClient": {
                    "UserPoolId": "eu-central-1_5wvFbUNEg",
                    "ClientName": "backend-auth",
                    "ClientId": "368l7detipe8dnc4foi7ht0gk7",
                    "LastModifiedDate": 1611700609.341,
                    "CreationDate": 1611700609.341,
                    "RefreshTokenValidity": 30,
                    "AllowedOAuthFlowsUserPoolClient": false
                }
            }
     */
    return new Promise((resolve, reject) => {
        cognitoidentityserviceprovider.adminInitiateAuth(params, function (err, data) {
            if (err) {
                console.log(err, err.stack) // an error occurred
            } else {
                console.log(data.AuthenticationResult)

                const header = JSON.parse(Buffer.from(data.AuthenticationResult.IdToken.split('.')[0], 'base64').toString('ascii'))
                const validated = jsonwebtoken.verify(data.AuthenticationResult.IdToken, pems[header.kid], {algorithms: ['RS256']})
                resolve(validated)
            }
        })
    })
}

(async () => {
    /**
     * retrieve the keys for later use
     */
    const keys = await axios.get(keysUrl)
    const pems = {}

    for (let k of keys.data.keys) {
        pems[k.kid] = jwkToPem(k)
    }

    const tokens = []
    for (let user of users) {
        params.AuthParameters = user
        tokens.push(await performAdminAuth(params, pems))
    }

    console.log(tokens)
})()