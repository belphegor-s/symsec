# SymSec

SymSec is a cryptographic utility for sealing and unsealing JSON objects using symmetric key encryption with message integrity verification in Node.js. This utility provides a simple and secure way to encrypt sensitive data in a JSON object and verify its integrity, ensuring that the data has not been tampered with in transit or storage. It uses the AES-256-GCM encryption algorithm, which provides strong encryption and authentication of the data, and generates a random initialization vector for each encryption to further enhance security.


### Local Setup

- Make sure you have latest version of pnpm install (install via `npm i -g pnpm`)
- Clone the repo and install dependencies via `pnpm i`
- Run the test via `pnpm test`
- Build the src via `pnpm build`