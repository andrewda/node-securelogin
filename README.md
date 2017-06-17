# Node SecureLogin

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

### verify(sltoken[, options])

- `sltoken` - A SecureLogin token
- `options` - (optional) An object containing zero or more options
    - `domains` - A string or array of strings containing acceptable
    client/provider domain(s)
    - `ignoreProvider` - Ignore provider domain name
    - `ignoreClient` - Ignore client domain name
    - `ignoreExpiration` - Ignore the token expiration date
