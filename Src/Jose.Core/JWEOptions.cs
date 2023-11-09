using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jose.Core
{
    public class JWEOptions
    {
        public string Issuer { get; set; } = "sca.service.com";

        public string SigningKey { get; set; } = string.Empty;

        public string EncryptionKey { get; set; } = string.Empty;

        public Dictionary<string, int> Expiry = new Dictionary<string, int>() { { "test.audience", 86400 * 40 } };
    }
}
