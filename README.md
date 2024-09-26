# Sainsbury SmartShop Auth Token Gen

When automating logging into Sainbury's SmartShop via requests, you encouter a issue. Login requires a Basic Auth. As it's generated clientside, we reversed it.

**Structs, Functions and other important stuff**

1. **C4506b**: The main struct that holds the RSA public key, AES cipher, and error logging service.
2. **ErrorLoggerService**: A simple logger that logs errors with a specific format.
3. **NewC4506b**: The constructor function that initializes a new `C4506b` instance from a public key string and a key generator function.

**Methods**

1. **m19284a**: Encrypts data using the RSA algorithm and returns the encrypted bytes as a base64-encoded string.
2. **m19285b**: Encrypts a string by calling `m19284a` on its byte representation.
3. **m19898b**: Generates an authentication token by encrypting a specific string using the AES cipher, and returns it as a base64-encoded string.
4. **Encrypt**: The main entry point that calls `m19898b` to generate an authentication token.

Hopefully this gives anyone using this more insight in how it works. 
