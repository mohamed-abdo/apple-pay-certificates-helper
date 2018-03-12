# apple-pay-certificates-helper
.net utility helper library to facilitate apple pay certificates creation, validation, and other related functionality, focusing on  ECC "Elliptic Curve Cryptography" 256 &amp; RSA 2048 algorithms. pkcs10, pkcs7 and pkcs12 standard, this helper uses bouncy castle as well to manage low level cryptography operations.

#The following functionality are provided:

Generate AsymmetricCipherKeyPair using Elliptic Curve Cypher with 256 Key

Generate AsymmetricCipherKeyPair using RSA with 2048 Key

Generate ISignatureFactory with Elliptic Curve Cypher Signature

Generate ISignatureFactory with RSA Signature

Extract AsymmetricCipherKeyPair "Private Key" from base64 string key

Create Pkcs10 Certificate using Elliptic Curve Cypher alogorithm

Create Pkcs10 Certificate using RSA Algorithm

Generate Pkcs10 Certificate signing request "CSR" with ECC 256 algorithm

Generate Pkcs10 Certificate signing request "CSR" with RSA 2048 algorithm

Generate Pkcs12 Certificate signing request "CSR" with ECC 256 algorithm

Generate Pkcs12 Certificate signing request "CSR" with RSA 2048 algorithm

Generate PEM from RSA XML String

Extract Public Key from Privarte key "base64 string" with ECC 256 algorithm

Extract Public Key from Privarte key "base64 string" with RSA 2048 algorithm

Extract Public Key from Privarte key "AsymmetricCipherKeyPair" with ECC 256 algorithm

Extract Public Key from Privarte key "AsymmetricCipherKeyPair" with RSA 2048 algorithm

Verify a certificate has been generated from Certificate signing request "CSR", by private key "base64 string" from CSR and the certificate public key "bytes array" with ECC 256 algorithm.

Verify a certificate has been generated from Certificate signing request "CSR", by private key "base64 string" from CSR and the certificate public key "bytes array" with RSA 2048 algorithm.

