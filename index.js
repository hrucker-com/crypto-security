'use strict';

const crypto = require('crypto');
const fs = require('fs').promises;
const zlib = require('zlib');
const { promisify } = require('util');
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

const data = {
    /**
     * Encrypts data using the specified algorithm.
     * @param {string} password - The encryption password.
     * @param {string} data - The data to encrypt.
     * @param {string} [algorithm='aes-256-gcm'] - The encryption algorithm.
     * @returns {Promise<object|boolean>} The encryption result or false on failure.
     */
    encrypt: async (password, data, algorithm = 'aes-256-gcm') => {
        try{
            if(crypto.getCiphers().includes(algorithm)){
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv(algorithm, crypto.scryptSync(password, 'salt', 32), iv);
                const encrypted = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]);
                const result = Buffer.concat([Buffer.from(algorithm.slice(0, 16).padEnd(16, '=')), iv,cipher.getAuthTag(),encrypted]);
                return {
                    algorithm: algorithm,
                    iv: {bin: iv, hex: iv.toString('hex')},
                    data: { bin: encrypted, hex: encrypted.toString('hex')},
                    result: { bin: result, hex: result.toString('hex')}
                };
            } else {
                return false;
            }
        } catch(e){
            return false;
        }
    },
    /**
     * Decrypts encrypted data.
     * @param {string} password - The decryption password.
     * @param {Buffer|string} data - The encrypted data.
     * @returns {Promise<object|boolean>} The decryption result or false on failure.
     */
    decrypt: async (password, data) => {
        try{
            if(Buffer.isBuffer(data) || typeof data === 'string'){
                data = typeof data === 'string' ? Buffer.from(data, 'hex') : data;
                const algorithm = data.slice(0, 16).toString().replace(/[= ]/g, '');
                const iv = data.slice(16, 32);
                const decipher = crypto.createDecipheriv(algorithm, crypto.scryptSync(password, 'salt', 32), iv);
                decipher.setAuthTag(data.slice(32, 48));
                const decrypted = Buffer.concat([decipher.update(data.slice(48)), decipher.final()]);
                return {
                    algorithm: algorithm,
                    iv: {
                        bin: iv,
                        hex: iv.toString('hex'),
                    },
                    data: {
                        bin: data,
                        hex: data.toString('hex'),
                    },
                    result: {
                        bin: decrypted,
                        hex: decrypted.toString(),
                    }
                }
            } else {
                return false;
            }
        } catch(e){
            return false;
        }
    }
};

const file = {
    /**
     * Encrypts and saves data to a file.
     * @param {string} password - The encryption password.
     * @param {string} data - The data to encrypt.
     * @param {string} [file_from='encrypted_data.bin'] - The output file.
     * @param {string} [algorithm='aes-256-gcm'] - The encryption algorithm.
     * @returns {Promise<boolean>} True if successful, otherwise false.
     */
    encrypt: async (password, data, file_from = 'encrypted_data.bin', algorithm = 'aes-256-gcm') => {
        try{
            const cr = await module.exports.data.encrypt(password, data, algorithm);
            if(cr){
                await fs.writeFile(file_from, await gzip(cr.result.bin));
                return true;
            } else {
                return false;
            }
        } catch(e){
            console.log(e)
            return false;
        }
    },
    decrypt:{
        /**
         * Decrypts a file and saves the output.
         * @param {string} password - The decryption password.
         * @param {string} [file_from='encrypted_data.bin'] - The input file.
         * @param {string} [file_to='decrypted_data.txt'] - The output file.
         * @returns {Promise<boolean>} True if successful, otherwise false.
         */
        to_file: async (password, file_from = 'encrypted_data.bin', file_to = 'decrypted_data.txt') => {
            try{
                if(fs.access(file_from, fs.constants.F_OK)){
                    const fd = await gunzip(await fs.readFile(file_from));
                    if(fd){
                        const cr = await module.exports.data.decrypt(password, fd);
                        await fs.writeFile(file_to, cr.result.bin);
                        return true;
                    }  else {
                        return false;
                    }
                } else {
                    return false;
                }
            } catch(e){
                return false;
            }
        },
        /**
         * Decrypts a file and returns the decrypted data.
         * @param {string} password - The decryption password.
         * @param {string} [file_from='encrypted_data.bin'] - The input file.
         * @returns {Promise<object|boolean>} The decrypted data or false on failure.
         */
        get_data: async (password, file_from = 'encrypted_data.bin') => {
            try{
                if(fs.access(file_from, fs.constants.F_OK)){
                    const fd = await gunzip(await fs.readFile(file_from));
                    if(fd){
                        const cr = await module.exports.data.decrypt(password, fd);
                        if(cr){
                            return cr;
                        } else{
                            return false;
                        }
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            } catch(e){
                return false;
            }
        },
        /**
         * Decrypts a file and returns the decrypted text.
         * @param {string} password - The decryption password.
         * @param {string} [file_from='encrypted_data.bin'] - The input file.
         * @returns {Promise<string|boolean>} The decrypted text or false on failure.
         */
        get_text: async (password, file_from = 'encrypted_data.bin') => {
            try{
                if(fs.access(file_from, fs.constants.F_OK)){
                    const fd = await gunzip(await fs.readFile(file_from));
                    if(fd){
                        const cr = await module.exports.data.decrypt(password, fd);
                        if(cr){
                            return cr.result.bin.toString();
                        } else{
                            return false;
                        }
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            } catch(e){
                return false;
            }
        }
    }
};

module.exports = { data, file };
