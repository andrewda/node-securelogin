const SecureLogin = require('..');

describe('SecureLogin', () => {

    it('should export verify method', () => {
        expect(SecureLogin.verify).to.be.a('function');
    });

});
