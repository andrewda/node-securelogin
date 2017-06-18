const nacl = require('ecma-nacl');
const url = require('url');

function csv(str) {
    return str.split(',').map((s) => {
        return decodeURIComponent(s);
    });
}

const parse = (sltoken) => {
    if (!sltoken) throw new TypeError('parse requires a SecureLogin token');

    sltoken = csv(sltoken);

    if (sltoken.length < 4) throw new TypeError('invalid SecureLogin token')

    const message = csv(sltoken[0]);
    const signatures = csv(sltoken[1]);
    const authkeys = csv(sltoken[2]);

    return {
        email: sltoken[3],
        message: {
            raw: sltoken[0],
            provider: message[0],
            client: message[1],
            scope: message[2],
            expiration: message[3],
        },
        signatures: {
            signature: signatures[0],
            hmac: signatures[1]
        },
        authkeys: {
            public: authkeys[0],
            secret: authkeys[1]
        }
    };
};

const verify = (sltoken, opts = { domains: [] }) => {
    if (!sltoken) throw new TypeError('verify requires a SecureLogin token');

    if (opts.domains.constructor !== Array) {
        opts.domains = [opts.domains];
    }

    const parsed = parse(sltoken);

    let errors = [];

    try {
        if (!nacl.signing.verify(new Buffer(parsed.signatures.signature, 'base64'), new Buffer(parsed.message.raw, 'utf8'), new Buffer(parsed.authkeys.public, 'base64'))) {
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

    if (domains.indexOf(url.parse(parsed.message.provider).host) === -1 && !opts.ignoreProvider) errors.push('Invalid provider');
    if (domains.indexOf(url.parse(parsed.message.client).host) === -1 && !opts.ignoreClient) errors.push('Invalid client');
    if (parsed.message.expiration < Date.now() / 1000 && !opts.ignoreExpiration) errors.push('Expired token');

    if (errors.length > 0) {
        return { errors };
    } else {
        return parsed;
    }
};

module.exports = { parse, verify };
