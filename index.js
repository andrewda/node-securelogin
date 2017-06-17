const ed25519 = require('ed25519');
const url = require('url');

function csv(str) {
    return str.split(',').map((s) => {
        return decodeURIComponent(s);
    });
}

module.exports.verify = (sltoken, opts) => {
    opts = opts || {};

    if (opts.domains) {
        if (opts.domains.constructor !== Array) {
            opts.domains = [opts.domains];
        }
    } else {
        opts.domains = [];
    }

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

    const domains = opts.domains.map((domain) => {
        return url.parse(domain).host;
    });

    if (domains.indexOf(url.parse(provider).host) === -1) error = 'Invalid provider';
    if (domains.indexOf(url.parse(client).host) === -1) error = 'Invalid client';
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
