import { randomBytes, createCipheriv, createDecipheriv, CipherGCM } from "crypto";

interface SealedJSON {
    data: string;
    iv: string;
    tag: string;
}

const ALGORITHM = 'aes-256-gcm';

class SymSec {
    private secretKey: Buffer;

    constructor(secretKey: string) {
        if (secretKey.length !== 64) {
            throw new Error('Invalid key length. The secretKey must be 32 bytes in hexadecimal format.');
        }

        this.secretKey = Buffer.from(secretKey, 'hex');
    }

    private getSecretKey(): Buffer {
        return this.secretKey;
    }

    seal(data: object): SealedJSON {
        const iv = randomBytes(32);
        const cipher = createCipheriv(ALGORITHM, this.getSecretKey(), iv);

        const jsonData = JSON.stringify(data);

        const encryptedData = Buffer.concat([
            cipher.update(Buffer.from(jsonData, 'utf-8')),
            cipher.final()
        ]).toString('hex');

        const tag = cipher.getAuthTag().toString('hex');
        return { data: encryptedData, iv: iv.toString("hex"), tag };
    }

    unseal(sealedJson: SealedJSON): object {
        const iv = Buffer.from(sealedJson.iv, 'hex');
        const tag = Buffer.from(sealedJson.tag, 'hex');
        const decipher = createDecipheriv(ALGORITHM, this.getSecretKey(), iv);
        decipher.setAuthTag(tag);
        
        const decryptedData = decipher.update(sealedJson.data, 'hex', 'utf-8');
        const originalData = JSON.parse(decryptedData + decipher.final('utf-8'));

        return originalData;
    }
}

export default SymSec;

export { SealedJSON };
