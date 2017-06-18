# Node SecureLogin

[![Travis][travis-img]][travis-url]
[![Release][release-img]][release-url]
[![Downloads][downloads-img]][downloads-url]
[![License][license-img]][license-url]

A tiny module used to verify SecureLogin tokens.

## Installation

```bash
npm install securelogin --save
```

## Usage

```javascript
const SecureLogin = require('securelogin');

const sltoken = 'https%3A%2F%2Fmy.app%252Chttps%3A%2F%2Fmy.app%2Fsecurelogin%252C%252C1496586322%2C2YNnncbnq7won%2B13AzJJqeBRREA9CTjYq%2FDwuGQAGy8LaQGnuH6OE10oLxV4kgJJhflnqdu0qY8bBC08v969Cg%3D%3D%252C%2Fbf0P0dBdDcQlak07UZpR4YnzPc2qw40jCSz1NAuw%2Bs%3D%2Ckdbjcc08YBKWdCY56lQJIi92wcGOW%2BKcMvbSgHN6WbU%3D%252C1uP20QU%2BWYvFf1KAxn3Re0ZYd2pm5vLdQhgkXTCjl44%3D%2Chomakov%40gmail.com';

SecureLogin.verify(decodeURIComponent(sltoken), {
    domains: 'https://my.app/',
    ignoreExpiration: true
});

/**
 * { provider: 'https://my.app',
 *   client: 'https://my.app/securelogin',
 *   scope: '',
 *   expiration: '1496586322',
 *   email: 'homakov@gmail.com',
 *   pubkey: 'kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=',
 *   secret: '1uP20QU+WYvFf1KAxn3Re0ZYd2pm5vLdQhgkXTCjl44=' }
 */
```

## API Reference

### parse(sltoken)

- `sltoken` - A SecureLogin token

Parses a SecureLogin token and returns an object with the token's contents.

Example return data:

```javascript
{
    email: 'example@email.com',
    message: {
        raw: 'http://localhost:3001,http://localhost:3001,,4651339663',
        provider: 'http://localhost:3001',
        client: 'http://localhost:3001',
        scope: '',
        expiration: '4651339663'
    },
    signatures: {
        signature: 'gjs+D1dTCf8FFHWmQizu7Nlt9uVm4jRhEG3J96gzktGKj5IkQcOb+qkJyTEBt9LY99pqqNrtKwxXNrlRyvocAA==',
        hmac: 'UNKOGVd/odZL071ic8sGijtAuBF6Jc262nSAI4O+El4='
    },
    authkeys: {
        public: 'FPS/onjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE=',
        secret: 'bruQ61utUBPay5QJ6Rity4S6AW+sma4NTt+7udhMveM='
    }
}
```

### verify(sltoken[, options])

- `sltoken` - A SecureLogin token
- `options` - (optional) An object containing zero or more options
    - `domains` - A string or array of strings containing acceptable
    client/provider domain(s)
    - `ignoreProvider` - Ignore provider domain name
    - `ignoreClient` - Ignore client domain name
    - `ignoreExpiration` - Ignore the token expiration date

Verifies a SecureLogin token and, if successful, returns the parsed object (see
[`parse` method](#parse(sltoken)) above). If unsuccessful, returns an object
with the `errors` property, an array of errors that occurred while parsing the
token.

<!-- Badges -->

[travis-img]: https://img.shields.io/travis/andrewda/node-securelogin.svg?style=flat-square
[travis-url]: https://travis-ci.org/andrewda/node-securelogin
[release-img]: https://img.shields.io/npm/v/securelogin.svg?style=flat-square
[release-url]: https://www.npmjs.com/package/securelogin
[downloads-img]: https://img.shields.io/npm/dm/securelogin.svg?style=flat-square
[downloads-url]: https://www.npmjs.com/package/securelogin
[license-img]: https://img.shields.io/npm/l/securelogin.svg?style=flat-square
[license-url]: https://github.com/andrewda/node-securelogin/blob/master/LICENSE
