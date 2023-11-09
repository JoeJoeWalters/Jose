using Jose.Core;
using Microsoft.Extensions.Options;
using System.ComponentModel;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Jose.Tests
{
    public class EncryptionTests
    {
        private IOptions<JWEOptions> _options;

        public EncryptionTests()
        {

            JWEOptions settings = new JWEOptions();

            settings.EncryptionKey = Guid.NewGuid().ToString();
            settings.SigningKey = Guid.NewGuid().ToString();

            _options = Options.Create(settings);
        }

        [Fact]
        public void Encrypt_JWE()
        {
            // ARRANGE
            JWEBuilder builder = new JWEBuilder(_options);
            string audience = "test.audience";

            // ACT
            string encrypted = builder.Encrypt(new List<Claim>(){ new Claim("StepUp", "Y")}, new TimeSpan(ticks: 10000), audience);
            bool valid = builder.Validate(encrypted, audience);
            List<Claim> claims = builder.Decrypt(encrypted, audience);


            // ASSERT

        }
    }
}