import { SealedJSON } from "./index";

export interface SecureJsonOptions {
  secretKey: string;
  algorithm?: string;
}

/**
 * Seals a JSON object with symmetric key encryption and message integrity verification.
 *
 * @param data - The JSON object to be sealed.
 * @param options - Options for the encryption algorithm, including the secret key and algorithm name.
 * @returns The sealed JSON object, including the encrypted data, initialization vector, and message authentication tag.
 */
export function sealJSON(data: object, options: SecureJsonOptions): SealedJSON;

/**
 * Unseals a previously sealed JSON object with symmetric key decryption and message integrity verification.
 *
 * @param sealedJSON - The previously sealed JSON object, including the encrypted data, initialization vector, and message authentication tag.
 * @param options - Options for the decryption algorithm, including the secret key and algorithm name.
 * @returns The original JSON object.
 * @throws An error if the message authentication tag does not match, indicating that the sealed data may have been tampered with.
 */
export function unsealJSON(
  sealedJSON: SealedJSON,
  options: SecureJsonOptions,
): object;
