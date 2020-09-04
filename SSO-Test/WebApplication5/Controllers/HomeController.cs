using System;
using System.Web;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SSOtest.Models;

namespace SSOtest.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var ticks = DateTime.UtcNow.Ticks;   // current UTC date and time, in ticks
            var key = "uouUIHui235A";                // your client key
            var secret = "NO564NJusf";          // your client secret
            var ssn = "333221111";               // uniquely identifies a user
            var endpoint = "ushealthcenter.com/USHCSSO/SSOLoginUser";
            var sig = getSignature(ticks, secret, endpoint, ssn);

            return Redirect("https://" + endpoint + "?Signature=" + sig + "&ClientKey="
                            + key + "&Timestamp=" + ticks + "&Identifier=" + ssn);
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

