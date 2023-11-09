using JsonFlatten;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace Jose.Core
{
    public class JWEBuilder
    {
        private readonly IOptions<JWEOptions> _options;

        private readonly RsaSecurityKey _privateEncryptionKey;
        private readonly RsaSecurityKey _publicEncryptionKey;
        private readonly ECDsaSecurityKey _privateSigningKey;
        private readonly ECDsaSecurityKey _publicSigningKey;

        public JWEBuilder(IOptions<JWEOptions> options) 
        {
            _options = options;

            var encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
            var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation

            //var encryptionKid = "8524e3e6674e494f85c5c775dcd602c5";
            //var signingKid = "29b4adf8bcc941dc8ce40a6d0227b6d3";

            _privateEncryptionKey = new RsaSecurityKey(encryptionKey) { KeyId = _options.Value.EncryptionKey };
            _publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) { KeyId = _options.Value.EncryptionKey };
            _privateSigningKey = new ECDsaSecurityKey(signingKey) { KeyId = _options.Value.SigningKey };
            _publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) { KeyId = _options.Value.SigningKey };
        }

        public string Encrypt(Object input, TimeSpan expiry, string audience) 
        {
            var handler = new JsonWebTokenHandler();

            var claims = JObject.Parse(JsonConvert.SerializeObject(input)).Flatten();

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Audience = audience,
                Issuer = _options.Value.Issuer,
                Expires = DateTime.UtcNow.Add(expiry),
                Claims = claims,

                // private key for signing
                SigningCredentials = new SigningCredentials(
                    _privateSigningKey, SecurityAlgorithms.EcdsaSha256),

                // public key for encryption
                EncryptingCredentials = new EncryptingCredentials(
                    _publicEncryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
            });

            return token;
        }

        public bool Validate(string token, string audience)
        {
            var handler = new JsonWebTokenHandler();

            TokenValidationResult result = handler.ValidateTokenAsync(
                token,
                new TokenValidationParameters
                {
                    ValidAudience = audience,
                    ValidIssuer = _options.Value.Issuer,

                    // public key for signing
                    IssuerSigningKey = _publicSigningKey,

                    // private key for encryption
                    TokenDecryptionKey = _privateEncryptionKey
                }).Result;

            return result.IsValid;
        }

        public T Decrypt<T>(string token, string audience)
        {
            var handler = new JsonWebTokenHandler();

            TokenValidationResult result = handler.ValidateTokenAsync(
                token,
                new TokenValidationParameters
                {
                    ValidAudience = audience,
                    ValidIssuer = _options.Value.Issuer,

                    // public key for signing
                    IssuerSigningKey = _publicSigningKey,

                    // private key for encryption
                    TokenDecryptionKey = _privateEncryptionKey
                }).Result;

            JObject unflattened = result.Claims.Unflatten();
            return unflattened.ToObject<T>();
        }

    }
}