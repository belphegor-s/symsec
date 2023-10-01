import { randomBytes, createCipheriv, createDecipheriv, CipherGCM } from "crypto";

interface SealedJSON {
    data: string;
    iv: string;
    tag: string;
}

const ALGORITHM = 'aes-256-gcm';

class SymSec {
    private secretKey: string;

    constructor(secretKey: string) {
        this.secretKey = secretKey
    }

    private getSecretKey(): string {
        return this.secretKey;
    }

    seal(data: object): SealedJSON {
        const iv = randomBytes(32);
        const cipher: CipherGCM = createCipheriv(ALGORITHM, this.getSecretKey(), iv);

        const jsonData = JSON.stringify(data);

        const encryptedData = Buffer.concat([
            cipher.update(Buffer.from(jsonData, 'utf-8')),
            cipher.final()
        ]).toString('hex');

        const tag = cipher.getAuthTag().toString('hex');
        return { data: encryptedData, iv: iv.toString("hex"), tag };
    }

    unseal(sealedJson: SealedJSON, secretKey: string): object {
        const decipher = createDecipheriv(ALGORITHM, secretKey, Buffer.from(sealedJson.iv, "hex"));

        let decryptedData = decipher.update(sealedJson.data, "hex", "utf8");
        decryptedData += decipher.update(Buffer.from(sealedJson.tag, "hex"));
        decryptedData += decipher.final("utf8");
        return JSON.parse(decryptedData);
    }
}

export default SymSec;

export { SealedJSON };
