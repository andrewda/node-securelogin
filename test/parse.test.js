const SecureLogin = require('..');

describe('SecureLogin.parse', () => {

    const token1 = decodeURIComponent('http%3A%2F%2Flocalhost%3A3001%252Chttp%3A%2F%2Flocalhost%3A3001%252C%252C1497739033%2CxPuI02mctaYq1eFTeiTNr8SF23wZrzG80Uf%2FeJTKyQW5kg4OOVh7WFlyH%2BakR0i3IkU6QZUiG15T3Lu%2B2W43Cw%3D%3D%252CqQdcxrwRRIAdAdbnm%2BazLz4nP46BVWzI2GVFtHUdMAc%3D%2CFPS%2FonjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE%3D%252CbruQ61utUBPay5QJ6Rity4S6AW%2Bsma4NTt%2B7udhMveM%3D%2Cexample%40email.com');
    const token2 = decodeURIComponent('http%3A%2F%2Flocalhost%3A3001%252Chttp%3A%2F%2Flocalhost%3A3001%252C%252C4651339663%2Cgjs%2BD1dTCf8FFHWmQizu7Nlt9uVm4jRhEG3J96gzktGKj5IkQcOb%2BqkJyTEBt9LY99pqqNrtKwxXNrlRyvocAA%3D%3D%252CUNKOGVd%2FodZL071ic8sGijtAuBF6Jc262nSAI4O%2BEl4%3D%2CFPS%2FonjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE%3D%252CbruQ61utUBPay5QJ6Rity4S6AW%2Bsma4NTt%2B7udhMveM%3D%2Cexample%40email.com');

    const token1Success = {
        email: 'example@email.com',
        message: {
            _raw: 'http://localhost:3001,http://localhost:3001,,1497739033',
            provider: 'http://localhost:3001',
            client: 'http://localhost:3001',
            scope: { _raw: '' },
            expiration: '1497739033'
        },
        signatures: {
            signature: 'xPuI02mctaYq1eFTeiTNr8SF23wZrzG80Uf/eJTKyQW5kg4OOVh7WFlyH+akR0i3IkU6QZUiG15T3Lu+2W43Cw==',
            hmac: 'qQdcxrwRRIAdAdbnm+azLz4nP46BVWzI2GVFtHUdMAc='
        },
        authkeys: {
            public: 'FPS/onjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE=',
            secret: 'bruQ61utUBPay5QJ6Rity4S6AW+sma4NTt+7udhMveM='
        }
    };

    const token2Success = {
        email: 'example@email.com',
        message: {
            _raw: 'http://localhost:3001,http://localhost:3001,,4651339663',
            provider: 'http://localhost:3001',
            client: 'http://localhost:3001',
            scope: { _raw: '' },
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
    };

    it('should throw if token is undefined', () => {
        expect(
            SecureLogin.parse.bind(null)
        ).to.throw(TypeError, 'parse requires a SecureLogin token');
    });

    it('should throw if token is invalid format', () => {
        expect(
            SecureLogin.parse.bind(null, 'abc')
        ).to.throw(TypeError, 'invalid SecureLogin token');
    });

    it('should return correctly parsed object #1', () => {
        expect(
            SecureLogin.parse(token1)
        ).to.deep.equal(token1Success);
    });

    it('should return correctly parsed object #2', () => {
        expect(
            SecureLogin.parse(token2)
        ).to.deep.equal(token2Success);
    });

});
