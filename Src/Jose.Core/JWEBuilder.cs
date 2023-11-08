using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.InteropServices.JavaScript;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Jose.Core
{
    public class JWEBuilder
    {
        private readonly IOptions<JWEOptions> _options;

        public JWEBuilder(IOptions<JWEOptions> options) 
        {
            _options = options;
        }

        public byte[] Encrypt(List<Claim> claims, TimeSpan expiry) 
        {
            var serialised = JsonSerializer.Serialize(new JwtPayload(claims));
            string encrypted = JWE.Encrypt(serialised, new[] { new JweRecipient(JweAlgorithm.A256KW, _options.Value.EncryptionKey, null) }, JweEncryption.A256GCM);
            string base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(encrypted));
            return Encoding.UTF8.GetBytes(base64);
        }

    }
}