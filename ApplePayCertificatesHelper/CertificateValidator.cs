using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AgilePay.GeexGate.Api.Business.Rest.Helper
{
    internal static class CertificateValidator
    {
        private volatile static X509Certificate2 trustedCertifcate;
        private static readonly string[] oids = { "1.2.840.113635.100.6.29", "1.2.840.113635.100.6.2.14" };
        internal static X509Certificate2 LoadTrustedCertifcated(byte[] certificateData)
        {
            if (trustedCertifcate == null)
            {
                return trustedCertifcate = new X509Certificate2(certificateData);
            }
            return trustedCertifcate;
        }
        internal static bool EnsureCertificateTrust(this X509Certificate2 trusterCertificate, X509Certificate2 certificateToValidate, Action<Exception> throwBusinessExceptoin)
        {
            //TODO:// verify by iod

            //validate certificate
            try
            {
                //var chainTrustValidator = X509CertificateValidator.ChainTrust;
                //it will throw exception in case of invalid certificate
                //To able to use this validation, certificate should be trusted on the running machine
                //chainTrustValidator.Validate(certificateToValidate);
                // test thumbprint for trusted certificate with the other certificate chain for same thumbprint.
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                chain.ChainPolicy.VerificationTime = DateTime.Now;
                chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0);

                // This part is very important. You're adding your known root here.
                // It doesn't have to be in the computer store at all. Neither certificates do.
                chain.ChainPolicy.ExtraStore.Add(trusterCertificate);
                bool isChainValid = chain.Build(certificateToValidate);

                if (!isChainValid)
                {
                    string[] errors = chain.ChainStatus
                        .Select(x => String.Format("{0} ({1})", x.StatusInformation.Trim(), x.Status))
                        .ToArray();
                    string certificateErrorsString = "Unknown errors.";

                    if (errors != null && errors.Length > 0)
                    {
                        certificateErrorsString = String.Join(", ", errors);
                    }
                    throwBusinessExceptoin(new ArgumentException($"Trust chain did not complete, due to the unknown certifcate authority. Errors:{ certificateErrorsString}"));
                }
                // This piece makes sure it actually matches your known root
                if (!chain.ChainElements
                    .Cast<X509ChainElement>()
                    .Any(x => x.Certificate.Thumbprint == trusterCertificate.Thumbprint))
                {
                    throwBusinessExceptoin(new ArgumentException("Trust chain did not complete, due to the unknown certificate authority. Thumbprints did not match."));
                }

                //TODO: validate certificate OIDs
                return true;
            }
            catch (CryptographicException cex)
            {
                throwBusinessExceptoin(new ArgumentException("Certificate chain trsut cannot be validated.", cex));
                return false;
            }
            catch (Exception ex)
            {
                throwBusinessExceptoin(new ArgumentException("Certificate cannot be validated.", ex));
                return false;
            }
        }

        internal static X509Certificate2 GetTrustedCertificate(byte[] trustedData, Action<Exception> throwBusinessExceptoin)
        {
            if (trustedData == null)
                throw new ArgumentNullException("trustedData is null");
            var content = new ContentInfo(trustedData);
            SignedCms signedCMS = new SignedCms();
            try
            {
                // read certificate.
                signedCMS.Decode(trustedData);
                // only one signer is supported by this code (and hopefully by ApplePay)
                if (signedCMS.Certificates.Count != 1)
                {
                    throwBusinessExceptoin(new ArgumentException($"There should be only one certificate in the trusted certificate. There was {signedCMS.Certificates.Count} in the integrator configuration."));
                }
                return signedCMS.Certificates[0];
            }
            catch (CryptographicException cex)
            {
                throwBusinessExceptoin(new ArgumentException("Signature cannot be validated.", cex));
                return null;
            }
            catch (Exception ex)
            {

                throw ex;
            }
        }

        public static byte[] Sign(byte[] data, X509Certificate2 certificate)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (certificate == null)
                throw new ArgumentNullException("certificate");
            // setup the data to sign
            ContentInfo content = new ContentInfo(data);
            SignedCms signedCms = new SignedCms(content, true);
            CmsSigner signer = new CmsSigner(certificate);
            signer.IncludeOption = X509IncludeOption.WholeChain;
            // create the signature
            signedCms.ComputeSignature(signer, true);
            return signedCms.Encode();
        }

        internal static bool Verify(byte[] signature, X509Certificate2 certificate)
        {
            if (signature == null)
                throw new ArgumentNullException("signature is null");
            if (certificate == null)
                throw new ArgumentNullException("certificate is null");
            // decode the signature
            SignedCms verifyCms = new SignedCms();
            // verify it
            try
            {
                verifyCms.Decode(signature);
                verifyCms.CheckSignature(new X509Certificate2Collection(certificate), false);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }
        internal static byte[] ExtractEnvelopedData(byte[] signature)
        {
            if (signature == null)
                throw new ArgumentNullException("signature");

            // decode the signature
            SignedCms cms = new SignedCms();
            cms.Decode(signature);

            if (cms.Detached)
                throw new InvalidOperationException("Cannot extract enveloped content from a detached signature.");

            return cms.ContentInfo.Content;
        }

    }
}
