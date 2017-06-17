const SecureLogin = require('..');

describe('SecureLogin.verify', () => {

    const invalidToken = decodeURIComponent('http%3A%2F%2Flocalhost%3A3001%252Chttp%3A%2F%2Flocalhost%3A3001%252C%252C4697739033%2CxPuI02mctaYq1eFTeiTNr8SF23wZrzG80Uf%2FeJTKyQW5kg4OOVh7WFlyH%2BakR0i3IkU6QZUiG15T3Lu%2B2W43Cw%3D%3D%252CqQdcxrwRRIAdAdbnm%2BazLz4nP46BVWzI2GVFtHUdMAc%3D%2CFPS%2FonjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE%3D%252CbruQ61utUBPay5QJ6Rity4S6AW%2Bsma4NTt%2B7udhMveM%3D%2Cexample%40email.com');
    const expiredToken = decodeURIComponent('http%3A%2F%2Flocalhost%3A3001%252Chttp%3A%2F%2Flocalhost%3A3001%252C%252C1497739033%2CxPuI02mctaYq1eFTeiTNr8SF23wZrzG80Uf%2FeJTKyQW5kg4OOVh7WFlyH%2BakR0i3IkU6QZUiG15T3Lu%2B2W43Cw%3D%3D%252CqQdcxrwRRIAdAdbnm%2BazLz4nP46BVWzI2GVFtHUdMAc%3D%2CFPS%2FonjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE%3D%252CbruQ61utUBPay5QJ6Rity4S6AW%2Bsma4NTt%2B7udhMveM%3D%2Cexample%40email.com');
    const validToken = decodeURIComponent('http%3A%2F%2Flocalhost%3A3001%252Chttp%3A%2F%2Flocalhost%3A3001%252C%252C4651339663%2Cgjs%2BD1dTCf8FFHWmQizu7Nlt9uVm4jRhEG3J96gzktGKj5IkQcOb%2BqkJyTEBt9LY99pqqNrtKwxXNrlRyvocAA%3D%3D%252CUNKOGVd%2FodZL071ic8sGijtAuBF6Jc262nSAI4O%2BEl4%3D%2CFPS%2FonjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE%3D%252CbruQ61utUBPay5QJ6Rity4S6AW%2Bsma4NTt%2B7udhMveM%3D%2Cexample%40email.com');

    const expiredTokenSuccess = {
        client: 'http://localhost:3001',
        email: 'example@email.com',
        expiration: '1497739033',
        provider: 'http://localhost:3001',
        pubkey: 'FPS/onjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE=',
        scope: '',
        secret: 'bruQ61utUBPay5QJ6Rity4S6AW+sma4NTt+7udhMveM='
    };

    const validTokenSuccess = {
        client: 'http://localhost:3001',
        email: 'example@email.com',
        expiration: '4651339663', // This will fail on June 17, 2117 but that won't be my problem
        provider: 'http://localhost:3001',
        pubkey: 'FPS/onjSa0ojlSzp9zXEiot5MgZcMwXR0sAIdgJMxaE=',
        scope: '',
        secret: 'bruQ61utUBPay5QJ6Rity4S6AW+sma4NTt+7udhMveM='
    };

    SecureLogin.verify(validToken, {
        domains: 'https://localhost:3001'
    })

    it('should throw if token is undefined', () => {
        expect(
            SecureLogin.verify.bind(null)
        ).to.throw(TypeError, 'verify requires a SecureLogin token');
    });

    it('should throw if token is invalid format', () => {
        expect(
            SecureLogin.verify.bind(null, 'abc', { domains: 'http://localhost:3001' })
        ).to.throw(TypeError, 'invalid SecureLogin token');
    });

    it('should return errors if token is invalid', () => {
        expect(
            SecureLogin.verify(invalidToken, { domains: 'http://localhost:3001' })
        ).to.deep.equal({ errors: [ 'Invalid signature' ] });
    });

    it('should return errors if token is expired', () => {
        expect(
            SecureLogin.verify(expiredToken, { domains: 'http://localhost:3001' })
        ).to.deep.equal({ errors: [ 'Expired token' ] });
    });

    it('should return errors if provider and/or client are incorrect', () => {
        expect(
            SecureLogin.verify(validToken, { domains: 'https://another.app' })
        ).to.deep.equal({ errors: [ 'Invalid provider', 'Invalid client' ]});
    });

    it('should ignore expired token if asked to', () => {
        expect(
            SecureLogin.verify(expiredToken, { domains: 'http://localhost:3001', ignoreExpiration: true })
        ).to.deep.equal(expiredTokenSuccess);
    });

    it('should accept valid token', () => {
        expect(
            SecureLogin.verify(validToken, { domains: 'https://localhost:3001' })
        ).to.deep.equal(validTokenSuccess);
    });

});
