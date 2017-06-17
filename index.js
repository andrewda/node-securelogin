const ed25519 = require('ed25519');
const url = require('url');

function csv(str) {
    return str.split(',').map((s) => {
        return decodeURIComponent(s);
    });
}

module.exports.verify = (sltoken, opts = { domains: [] }) => {
    if (opts.domains.constructor !== Array) {
        opts.domains = [opts.domains];
    }

    sltoken = csv(sltoken);

    const message = csv(sltoken[0]);
    const signatures = csv(sltoken[1]);
    const authkeys = csv(sltoken[2]);
    const email = sltoken[3];

    const provider = message[0];
    const client = message[1];
    const scope = message[2];
    const expiration = message[3];

    const signature = signatures[0];
    const hmac_signature = signatures[1];

    const pubkey = authkeys[0];
    const secret = authkeys[1];

    let errors = [];

    try {
        if (!ed25519.Verify(new Buffer(sltoken[0], 'utf8'), new Buffer(signature, 'base64'), new Buffer(pubkey, 'base64'))) {
            errors.push('Invalid signature');
        }
    } catch(e) {
        errors.push('Invalid signature');
    }

    const domains = opts.domains.map((domain) => {
        // Check if domain has protocol – if not, prefix it with "http://"
        // `url.parse` won't work on localhost:3000, but will on http://localhost:3000
        if (domain.indexOf('http://') !== 0 && domain.indexOf('https://') !== 0) {
            domain = `http://${domain}`;
        }

        return url.parse(domain).host;
    });

    if (domains.indexOf(url.parse(provider).host) === -1 && !opts.ignoreProvider) errors.push('Invalid provider');
    if (domains.indexOf(url.parse(client).host) === -1 && !opts.ignoreClient) errors.push('Invalid client');
    if (expiration < Date.now() / 1000 && !opts.ignoreExpiration) errors.push('Expired token');

    if (errors.length > 0) {
        return { errors };
    } else {
        return { provider, client, scope, expiration, email, pubkey, secret };
    }
}
