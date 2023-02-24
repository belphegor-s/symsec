import crypto from "crypto";

interface SymSecOptions {
  secretKey: string;
  algorithm?: string;
}

interface SealedJSON {
  data: string;
  iv: string;
  tag: string;
}

class SymSec {
  static seal(
    data: object,
    secretKey: string,
    authTagLength = 16,
    algorithm = "aes-256-gcm",
  ): SealedJSON {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv, {
      authTagLength,
    });
    const jsonData = JSON.stringify(data);
    let encryptedData = cipher.update(jsonData, "utf8", "hex");
    encryptedData += cipher.final("hex");
    const tag = cipher.getAuthTag().toString("hex");
    return { data: encryptedData, iv: iv.toString("hex"), tag };
  }

  static unseal(
    sealedJson: SealedJSON,
    secretKey: string,
    authTagLength = 16,
    algorithm = "aes-256-gcm",
  ): object {
    const decipher = crypto.createDecipheriv(
      algorithm,
      secretKey,
      Buffer.from(sealedJson.iv, "hex"),
      { authTagLength },
    );
    let decryptedData = decipher.update(sealedJson.data, "hex", "utf8");
    decryptedData += decipher.update(Buffer.from(sealedJson.tag, "hex"));
    decryptedData += decipher.final("utf8");
    return JSON.parse(decryptedData);
  }
}

export default SymSec;

export { SealedJSON };
