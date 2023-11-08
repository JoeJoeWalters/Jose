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

            Aes enc = Aes.Create();
            enc.GenerateIV();
            enc.GenerateKey();
            settings.EncryptionKey = enc.Key;
            settings.EncryptionIV = enc.IV;

            Aes sig = Aes.Create();
            sig.GenerateIV();
            sig.GenerateKey();
            settings.SigningKey = sig.Key;
            settings.SigningIV = sig.IV;

            _options = Options.Create(settings);
        }

        [Fact]
        public void Encrypt_JWE()
        {
            // ARRANGE
            JWEBuilder builder = new JWEBuilder(_options);

            // ACT
            builder.Encrypt(new List<Claim>(), new TimeSpan(ticks: 10000));

            // ASSERT

        }
    }
}