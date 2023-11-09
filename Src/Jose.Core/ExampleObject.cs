using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jose.Core
{
    public class ExampleObject
    {
        public SubObject SubObject { get; set; } = new SubObject();
    }

    public class SubObject
    {
        public string SubProperty { get; set; } = string.Empty;
    }
}
