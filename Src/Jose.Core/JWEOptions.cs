using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jose.Core
{
    public class JWEOptions
    {
        public byte[] SigningKey { get; set; }
        public byte[] SigningIV { get; set; }

        public byte[] EncryptionKey { get; set; }
        public byte[] EncryptionIV { get; set; }
    }
}
