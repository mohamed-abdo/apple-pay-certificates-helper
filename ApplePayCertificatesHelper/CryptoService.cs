using ApplePayCertificatesHelper.Models;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
/// <summary>
/// Developed By: Mohamed Abdo
///           On: 27 Aug 2017
///             : apple pay cryptography helper
/// </summary>
namespace AgilePay.GeexGate.Api.Business.Rest.Helper
{
    public class CryptoService
    {
        private const string ECC_ALG = "ECDSA";
        private const string RSA_SGN_ALG = "SHA256WithRSA";
        private const string ECC_SGN_ALG = "SHA256WITHECDSA";

        public static Func<CertificateProof, X509Name> GenerateCertificate = (proofs) =>
        {
            /**
             * @param CN
             *            Common Name that distinguishes your Organization
             * @param OU
             *            Organizational unit
             * @param O
             *            Organization NAME
             * @param L
             *            Location
             * @param S
             *            State
             * @param C
             *            Country
             */
            return new X509Name($"CN={proofs.Identifier}, O={proofs.Name}, C={proofs.Country}");
        };

        public static Func<AsymmetricCipherKeyPair> GenerateEllipticCurve256Key = () =>
        {
            //Key generation 256bits
            IAsymmetricCipherKeyPairGenerator bcKpGen = GeneratorUtilities.GetKeyPairGenerator(ECC_ALG);
            bcKpGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
            AsymmetricCipherKeyPair subjectKeyPair = bcKpGen.GenerateKeyPair();
            return subjectKeyPair;
        };

        public static Func<AsymmetricCipherKeyPair> GenerateRSA2048Key = () =>
        {
            //Key generation 2048bits
            const int strength = 2048;
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            return subjectKeyPair;
        };

        public static Func<AsymmetricCipherKeyPair, ISignatureFactory> GenerateRSASignature = (cipherkey) =>
        {
            ISignatureFactory signatureFacorty = new Asn1SignatureFactory(RSA_SGN_ALG, cipherkey.Private);
            return signatureFacorty;
        };

        public static Func<AsymmetricCipherKeyPair, ISignatureFactory> GenerateECCSignature = (cipherkey) =>
        {
            ISignatureFactory signatureFacorty = new Asn1SignatureFactory(ECC_SGN_ALG, cipherkey.Private);
            return signatureFacorty;
        };

        public static Func<AsymmetricCipherKeyPair, string> GetPrivateKey = (asymmetricCipherKey) =>
        {
            var CSRPem = new StringBuilder();
            var CSRPemWriter = new PemWriter(new StringWriter(CSRPem));
            //Convert BouncyCastle Private Key to .PEM file.
            StringBuilder PrivateKeyPem = new StringBuilder();
            PemWriter PrivateKeyPemWriter = new PemWriter(new StringWriter(PrivateKeyPem));
            PrivateKeyPemWriter.WriteObject(asymmetricCipherKey.Private);
            CSRPemWriter.Writer.Flush();
            var PrivateKeyEncoded = PrivateKeyPem.ToString();
            return PrivateKeyEncoded;
        };

        public static Func<AsymmetricCipherKeyPair, X509Name, Pkcs10CertificationRequest> CreateRSAPkcs10Certificate = (cipherKeys, certificate) =>
        {
            var signature = GenerateRSASignature(cipherKeys);
            return new Pkcs10CertificationRequest(signature, certificate, cipherKeys.Public, null, cipherKeys.Private);
        };

        public static Func<AsymmetricCipherKeyPair, X509Name, Pkcs10CertificationRequest> CreateECCPkcs10Certificate = (cipherKeys, certificate) =>
        {
            var signature = GenerateECCSignature(cipherKeys);
            return new Pkcs10CertificationRequest(signature, certificate, cipherKeys.Public, null, cipherKeys.Private);
        };

        public static Func<Pkcs10CertificationRequest, string> GenerateCSR = (certificateRequext) =>
        {
            //Convert BouncyCastle CSR to .PEM file.
            var CSRPem = new StringBuilder();
            var CSRPemWriter = new PemWriter(new StringWriter(CSRPem));
            CSRPemWriter.WriteObject(certificateRequext);
            CSRPemWriter.Writer.Flush();
            //the CSR Text 
            var CSREncoded = CSRPem.ToString();
            return CSREncoded;
        };

        public static Func<CertificateProof, KeyValuePair<string, string>> GenerateECCCertificateRequest = (proofs) =>
        {
            var cipher = GenerateEllipticCurve256Key();
            var csr = GenerateCSR(CreateECCPkcs10Certificate(
                cipher,
                GenerateCertificate(proofs)));
            var privateKey = GetPrivateKey(cipher);
            return new KeyValuePair<string, string>(csr, privateKey);
        };

        public static Func<CertificateProof, KeyValuePair<string, string>> GenerateRSACertificateRequest = (proofs) =>
        {
            var cipher = GenerateRSA2048Key();
            var csr = GenerateCSR(CreateRSAPkcs10Certificate(
                cipher,
                GenerateCertificate(proofs)));
            var privateKey = GetPrivateKey(cipher);
            return new KeyValuePair<string, string>(csr, privateKey);
        };

        private static AsymmetricCipherKeyPair GenerateECKeys(int keySize)
        {
            var gen = new ECKeyPairGenerator();
            var keyGenParam = new KeyGenerationParameters(new SecureRandom(), keySize);
            gen.Init(keyGenParam);
            return gen.GenerateKeyPair();
        }

        public static Func<string, RsaKeyParameters> ToRSAPublicKeyFromString = (privateKey) =>
        {
            var keyContent = new PemReader(new StringReader(privateKey));
            if (keyContent == null)
                throw new ArgumentNullException("private key is not valid!");
            var ciphrPrivateKey = (AsymmetricCipherKeyPair)keyContent.ReadObject();
            // Build RSA Key
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ciphrPrivateKey.Public);
            var serializedPublic = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            return (RsaKeyParameters)PublicKeyFactory.CreateKey(serializedPublic);
        };

        public static Func<AsymmetricCipherKeyPair, RsaKeyParameters> ToRSAPublicKeyFromCiphrKey = (ciphrKey) =>
        {
            // Build RSA Key
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ciphrKey.Public);
            var serializedPublic = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            return (RsaKeyParameters)PublicKeyFactory.CreateKey(serializedPublic);
        };

        public static Func<AsymmetricCipherKeyPair, byte[]> ToECCPublicKey = (privateKey) =>
        {
            // Get Private key bytes
            ECPrivateKeyParameters _ECCprivateKey = (ECPrivateKeyParameters)privateKey.Private;
            byte[] privateKeyBytes = _ECCprivateKey.D.ToByteArray();
            // Build ECC Curve
            X9ECParameters curve = SecNamedCurves.GetByName("SecP256r1");//SecObjectIdentifiers.SecP256r1
            ECDomainParameters domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            // Then calculate the public key only using domainParams.getG() and private key
            Org.BouncyCastle.Math.EC.ECPoint Q = domainParams.G.Multiply(new BigInteger(privateKeyBytes));
            return Q.GetEncoded();
        };

        public static Func<byte[], string, bool> VerifyECCKeys = (publicKey, privateKey) =>
        {
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentNullException("private key must contains value!");
            var privateKeyContent = new PemReader(new StringReader(privateKey));
            if (privateKeyContent == null)
                throw new ArgumentNullException("private key is not valid!");
            var ciphrPrivateKey = (AsymmetricCipherKeyPair)privateKeyContent.ReadObject();
            var publicKeyFromPrivateKey = ToECCPublicKey(ciphrPrivateKey);
            return publicKeyFromPrivateKey.SequenceEqual(publicKey);
        };

        public static Func<PublicKey, string, bool> VerifyRSAKeys = (publicKey, privateKey) =>
        {
            if (publicKey == null)
                throw new ArgumentNullException("public key must contains value!");
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentNullException("private key must contains value!");
            var publicKeyFromPrivateKey = ToRSAPublicKeyFromString(privateKey);
            var publicKeyChiper = DotNetUtilities.GetRsaPublicKey((RSACryptoServiceProvider)publicKey.Key);
            return (publicKeyFromPrivateKey.Exponent.CompareTo(publicKeyChiper.Exponent) == 0 &&
                   publicKeyFromPrivateKey.Modulus.CompareTo(publicKeyChiper.Modulus) == 0);
        };

        public static Func<X509Certificate2, string, byte[]> ToRSAPkcs12Certificate = (certificateV2, privateKey) =>
        {
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentNullException("private key must contains value!");
            var bouncyCertificate = DotNetUtilities.FromX509Certificate(certificateV2);

            var keyContent = new PemReader(new StringReader(privateKey));
            if (keyContent == null)
                throw new ArgumentNullException("private key is not valid!");
            var ciphrPrivateKey = (AsymmetricCipherKeyPair)keyContent.ReadObject();
            var asymmetricKey = new AsymmetricKeyEntry(ciphrPrivateKey.Private);
            var pkcs12Store = new Pkcs12StoreBuilder().Build();
            pkcs12Store.SetCertificateEntry(bouncyCertificate.SubjectDN.ToString() + "_certificate", new X509CertificateEntry(bouncyCertificate));
            pkcs12Store.SetKeyEntry(bouncyCertificate.SubjectDN.ToString() + "_RSA_2048_key", asymmetricKey, new X509CertificateEntry[] { new X509CertificateEntry(bouncyCertificate) });
            byte[] pkcs12Contents;
            using (var memoryStream = new MemoryStream())
            {
                pkcs12Store.Save(memoryStream, null, new SecureRandom());
                pkcs12Contents = memoryStream.ToArray();
            }
            return pkcs12Contents;
        };

        public static Func<X509Certificate2, string, byte[]> ToECCPkcs12Certificate = (certificateV2, privateKey) =>
        {
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentNullException("private key must contains value!");
            var bouncyCertificate = DotNetUtilities.FromX509Certificate(certificateV2);

            var privateKeyContent = new PemReader(new StringReader(privateKey));
            if (privateKeyContent == null)
                throw new ArgumentNullException("private key is not valid!");
            var ciphrECCPrivateKey = (AsymmetricCipherKeyPair)privateKeyContent.ReadObject();
            ECPrivateKeyParameters ECCprivateKey = (ECPrivateKeyParameters)ciphrECCPrivateKey.Private;
            var asymmetricKey = new AsymmetricKeyEntry(ECCprivateKey);
            var pkcs12Store = new Pkcs12StoreBuilder().Build();
            pkcs12Store.SetCertificateEntry(bouncyCertificate.SubjectDN.ToString() + "_certificate", new X509CertificateEntry(bouncyCertificate));
            pkcs12Store.SetKeyEntry(bouncyCertificate.SubjectDN.ToString() + "_ECC_256_key", asymmetricKey, new X509CertificateEntry[] { new X509CertificateEntry(bouncyCertificate) });
            byte[] pkcs12Contents;
            using (var memoryStream = new MemoryStream())
            {
                pkcs12Store.Save(memoryStream, null, new SecureRandom());
                pkcs12Contents = memoryStream.ToArray();
            }
            return pkcs12Contents;
        };
    }
}
