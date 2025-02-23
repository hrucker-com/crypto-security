const crypto_security = require('../index');

(async () => {

    const password = '1234554321';
    const data = 'Hello World!';
    

    console.log('data:', data);

    const encrypted = await crypto_security.data.encrypt(password, data);
    console.log('data encrypt:', encrypted);

    const decrypted = await crypto_security.data.decrypt(password, encrypted.result.bin);
    console.log('data decrypt:', decrypted);

    console.log();
    console.log('=======================================================================');
    console.log();

    console.log('file encrypt:', await crypto_security.file.encrypt(password, data));

    console.log('file decrypt to file:', await crypto_security.file.decrypt.to_file(password));

    console.log('file decrypt get data:', await crypto_security.file.decrypt.get_data(password));

    console.log('file decrypt get text:', await crypto_security.file.decrypt.get_text(password));

})()