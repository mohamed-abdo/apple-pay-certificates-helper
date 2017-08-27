using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApplePayCertificatesHelper.Models
{
    public class CertificateProof
    {
        public string Name { get; set; }
        public string Domain { get; set; }
        public string Country { get; set; }
        public string Identifier { get; set; }
    }
}
