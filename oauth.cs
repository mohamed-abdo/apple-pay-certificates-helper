public sealed class OAuthService
    {
        private readonly string onboardingUrl, consumerKey;
        private readonly AsymmetricAlgorithm privateKey;
        private const string onboardingEndPoint = "onboarding";

        public MasterPassService(string onboardingUrl, string consumerKey, AsymmetricAlgorithm privateKey)
        {
            if (string.IsNullOrEmpty(onboardingUrl))
                throw new ArgumentNullException("apiBaseUrl parameter is missing");
            this.onboardingUrl = onboardingUrl;
            if (string.IsNullOrEmpty(consumerKey))
                throw new ArgumentNullException("consumerKey parameter is missing");
            this.consumerKey = consumerKey;
            if (privateKey.KeySize == 0)
                throw new ArgumentNullException("privateKey parameter is invalid");
            this.privateKey = privateKey;
        }
        public string get_oauth_body_hash(string requestBody)
        {
            //since oauth v1 doesn't support 256
            var sha1 = new SHA1CryptoServiceProvider();
            sha1.Initialize();
            var hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(requestBody));
            return Convert.ToBase64String(hash);
        }

        private const string authHeader = "OAuth", JSONMediaType = "application/json", XMLMedaiType = "application/xml";

        private string oauth_partial_string(string oauth_consumer_key, string requestBody)
        {
            long oauth_timestamp = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds();
            const string oauth_version = "1.0";
            const string oauth_signature_method = "RSA-SHA1";
            string oauth_body_hash = get_oauth_body_hash(requestBody);
            string oauth_nonce = DateTimeOffset.UtcNow.Ticks.ToString();

            return $"oauth_consumer_key={oauth_consumer_key},oauth_nonce={oauth_nonce},oauth_timestamp={oauth_timestamp},oauth_version={oauth_version},oauth_body_hash={oauth_body_hash},oauth_signature_method={oauth_signature_method}";
        }
        private string generate_signature_base_string(string oauth_string)
        {
            const string HTTP_method = "POST";
            string encoded_oauth_string = WebUtility.UrlEncode(oauth_string);
            return $"{HTTP_method}&{onboardingUrl?.ToLower()}&{encoded_oauth_string}";
        }
        private string sign_base_string(string base_string)
        {
            var signer = privateKey as RSACryptoServiceProvider;
            if (signer == null)
                throw new ArgumentException("invalid RSA private key");
            var signedData = signer.SignData(Encoding.ASCII.GetBytes(base_string), new SHA1CryptoServiceProvider());
            string base64RSA = Convert.ToBase64String(signedData);
            string signature_encoded = WebUtility.UrlEncode(base64RSA);
            string signature_encoded_cleansed = signature_encoded
                .Replace("+", "%20")
                .Replace("*", "%2A")
                .Replace("%7E", "~");
            return signature_encoded_cleansed;
        }
        private string generate_oauth_header(string oauth_consumer_key, string requestBody)
        {
            var base_string = oauth_partial_string(oauth_consumer_key, requestBody);
            var signature_base_string = generate_signature_base_string(base_string);
            var oauth_signature = sign_base_string(signature_base_string);
            return $"{base_string},oauth_signature={oauth_signature}";
        }
        public MerchantUpload CreateAccount(string integratorIdentifier, MerchantUpload account, Action<HttpException> onError)
        {
            try
            {
                var client = new HttpClient();
                var request = new HttpRequestMessage()
                {
                    RequestUri = new Uri(onboardingUrl),
                    Content = new StringContent(account.ToXmlString(), Encoding.UTF8, XMLMedaiType),
                    Method = HttpMethod.Post,
                };
                var requestBody = account.ToXmlString();

                request.Headers.Add(authHeader, generate_oauth_header(consumerKey, requestBody));

                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(XMLMedaiType));
                client.BaseAddress = new Uri(onboardingUrl);
                var result = client.SendAsync(request).Result;
                var content = result.Content.ReadAsStringAsync().Result;
                if (!result.IsSuccessStatusCode)
                    if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        throw new Exception("Internal server issue, while connecting to MasterPass service.");
                    else
                    {
                        throw new Exception("Internal server error while processing your request with MasterPass.");
                    }
                //TODO:deserialize response on local typed object.
                return account;
            }
            catch (HttpException httpExp)
            {
                onError(httpExp);
                return null;
            }
            catch (Exception ex)
            {
                Logger.Error(ex.Message);
                throw new Exception(originalException: ex);
            }
        }
    }
