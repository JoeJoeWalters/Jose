using FluentAssertions;
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
        public void EncryptedThenDecryptedJWE_Should_RetainClaims()
        {
            // ARRANGE
            JWEBuilder builder = new JWEBuilder(_options);
            string audience = "test.audience";

            // ACT
            string encrypted = builder.Encrypt(new ExampleObject() { SubObject = new SubObject() { SubProperty = "Example" } }, new TimeSpan(ticks: 10000), audience);
            ExampleObject decrypted = builder.Decrypt<ExampleObject>(encrypted, audience);


            // ASSERT
            decrypted.SubObject.SubProperty.Should().Be("Example");

        }
    }
}