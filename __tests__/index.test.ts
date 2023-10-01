import { randomBytes } from 'crypto';
import SymSec, { SealedJSON } from '../src/index';

describe('SymSec', () => {
    const secretKey = randomBytes(32).toString('hex');
    const symSec = new SymSec(secretKey);

    describe('seal and unseal', () => {
        it('should correctly seal and unseal data', () => {
            const data = { message: 'Hello, World!' };
            const sealedData: SealedJSON = symSec.seal(data);
            const unsealedData = symSec.unseal(sealedData);
            expect(unsealedData).toMatchObject(data);
        });
    });
});
