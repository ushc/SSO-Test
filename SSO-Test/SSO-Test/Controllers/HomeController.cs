using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System;
using System.Web;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace SSO_Test.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var ticks = DateTime.UtcNow.Ticks;   // current UTC date and time, in ticks
            var key = "Aif6hnAJJ13";                // your client key
            var secret = "LJouuht654A";          // your client secret
            var ssn = "111223333";               // uniquely identifies a user
            var endpoint = "ushealthcenter.com/USHCSSO/SSOLoginUser";
            var sig = getSignature(ticks, secret, endpoint, ssn);
            var fullURL = "http://" + endpoint + "?Signature=" + sig + "&ClientKey="
                            + key + "&Timestamp=" + ticks + "&Identifier=" + ssn;

            return Redirect(fullURL);
        }

        public static string hashPair(string key, string body)
        {
            var enc = new HMACSHA1(Encoding.ASCII.GetBytes(key));

            return Convert.ToBase64String(enc.ComputeHash(Encoding.ASCII.GetBytes(body)));
        }

        public static string UpperCaseUrlEncode(string s)
        {
            char[] temp = HttpUtility.UrlEncode(s).ToCharArray();
            for (int i = 0; i < temp.Length - 2; i++)
            {
                if (temp[i] == '%')
                {
                    temp[i + 1] = char.ToUpper(temp[i + 1]);
                    temp[i + 2] = char.ToUpper(temp[i + 2]);
                }
            }
            return new string(temp);
        }

        public static string getSignature(long timestamp, string tokenSecret,
                                          string url, string identifier)
        {
            var sbod = "POST&" + UpperCaseUrlEncode(url) + "&" +
                       UpperCaseUrlEncode(identifier);
            var skey = UpperCaseUrlEncode(timestamp.ToString()) + "&" +
                       UpperCaseUrlEncode(tokenSecret);

            return UpperCaseUrlEncode(hashPair(skey, sbod));
        }
    }
}