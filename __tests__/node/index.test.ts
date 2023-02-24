import SymSec, { SealedJSON } from "../../src/index";

describe("SymSec", () => {
  const secretKey = "my-secret-key";
  const originalData = {
    username: "johndoe",
    email: "johndoe@example.com",
  };
  let sealedJSON: SealedJSON;

  const symsec = new SymSec({ secretKey });

  it("should seal JSON objects with a secret key", () => {
    sealedJSON = symsec.sealJSON(originalData);
    expect(sealedJSON).toBeDefined();
    expect(sealedJSON.data).toBeDefined();
    expect(sealedJSON.iv).toBeDefined();
    expect(sealedJSON.tag).toBeDefined();
  });

  it("should unseal previously sealed JSON objects with the correct secret key", () => {
    const unsealedData = symsec.unsealJSON(sealedJSON);
    expect(unsealedData).toEqual(originalData);
  });

  it("should throw an error when unsealing JSON objects with an incorrect secret key", () => {
    const wrongSecretKey = "wrong-secret-key";
    const symsecWithWrongSecretKey = new SymSec({ secretKey: wrongSecretKey });
    expect(() =>
      symsecWithWrongSecretKey.unsealJSON(sealedJSON),
    ).toThrowError();
  });
});
