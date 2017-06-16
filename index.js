const ed25519 = require('ed25519');

function csv(str) {
    return str.split(',').map((s) => {
        return decodeURIComponent(s);
    });
}

module.exports.verify = (sltoken, opts) => {
    sltoken = csv(sltoken);

    let message = csv(sltoken[0]);
    let signatures = csv(sltoken[1]);
    let authkeys = csv(sltoken[2]);
    let email = sltoken[3];

    let provider = message[0];
    let client = message[1];
    let scope = message[2];
    let expiration = message[3];

    let signature = signatures[0];
    let hmac_signature = signatures[1];

    let pubkey = authkeys[0];
    let secret = authkeys[1];

    let error = null;

    try {
        const verified = ed25519.Verify(new Buffer(sltoken[0], 'utf8'), new Buffer(signature, 'base64'), new Buffer(pubkey, 'base64'));
        if (!verified) error = 'Invalid signature';
    } catch(e) {
        error = 'Invalid signature';
    }

    let domains = opts.domains;

    if (domains !== provider || domains.indexOf(provider) === -1) error = 'Invalid provider';
    if (domains !== client || domains.indexOf(client) === -1) error = 'Invalid client';
    if (expiration < Date.now() / 1000) error = 'Expired token';

    if (error) {
        return { error: error };
    } else {
        return {
            provider: provider,
            client: client,
            scope: scope,
            expiration: expiration,
            email: email,
            pubkey: pubkey,
            secret: secret
        };
    }
}
