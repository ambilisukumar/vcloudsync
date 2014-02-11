/*#
# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This code is not supported by Google
#
*/
/**
* This script acquires an oauth2 access_token for use with authenticated GCS
* ShoppingAPI and ContentAPI requests.  GCS customers should use one of the
* libraries shown below to get the token in a production setting.  This script
* is provided to demonstrate the encryption and structure of getting an oauth2
* bearer tokens.  Ensure the computer this script is run on is synced with a
* NTP server.
* REFERENCE :
* https://developers.google.com/console/help/#service_accounts
* https://developers.google.com/commerce-search/docs/shopping_auth
* https://developers.google.com/accounts/docs/OAuth2ServiceAccount
* http://www.dotnetopenauth.net/
* http://msdn.microsoft.com/en-us/library/windows/desktop/bb931357(v=vs.85).aspx
*
*   c:\WINDOWS\Microsoft.NET\Framework\v4.0.30319\csc.exe /main:GCS.JWT *.cs
*
*   JWT.exe -client_id= -key=
*  
*     client_id=<clientID Service account  'email'>    
*     key = <private key for the service account> (e.g. c:\\privkey.p12)
*/
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Requests;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Auth.OAuth2.Web;
using Google.Apis.Authentication.OAuth2;
using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
using Google.Apis.Plus.v1;
using Google.Apis.Plus.v1.Data;
using Google.Apis.Services;
using Google.Apis.Util.Store;
using Google.Apis.Storage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Diagnostics;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Permissions;
using System.Security.Policy;
using System.Security.Principal;
using System.Security.Util;
using System.Net;
using System.IO;
using System.Threading;


namespace GCS
{
    class JWT
    {
      //  string client_Sec = "rMkXB6ZdyrYILKM9CE-KLqeb";
        string lauth_token;
      //  public static UserCredential credential;
        static void Main(string[] args)
        {


            String client_id = "933144605699-l5u74o4101bov3quvdk325hledk4hqjg@developer.gserviceaccount.com";

            String key = @"M:\TROV PROJECT\vidyajavasample-Auth&List(10Feb2014)\vidyajavasample\vidyajavasample\privatekey.p12";

            //GetMethod2(client_id, key);

            Console.WriteLine(client_id + "<<<============================>>>" + key);
                JWT j = new JWT(client_id, key);
                Console.Read();
         }
        public JWT(String client_id, String key)
        {
            String SCOPE = "https://www.googleapis.com/auth/devstorage.full_control";
            long now = unix_timestamp();
            long exp = now + 3600;

            Console.WriteLine("Now : " + now.ToString() + "\t Expreir  : " + exp.ToString());

            String jwt_header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

            String claim = "{\"iss\":\"" + client_id + "\",\"scope\":\"" + SCOPE +
                "\",\"aud\":\"https://accounts.google.com/o/oauth2/token\",\"exp\":" +
                exp + ",\"iat\":" + now + "}";
            
            
            System.Text.ASCIIEncoding e = new System.Text.ASCIIEncoding();

            String clearjwt = Base64UrlEncode(e.GetBytes(jwt_header)) + "." + Base64UrlEncode(e.GetBytes(claim));
            byte[] buffer = Encoding.Default.GetBytes(clearjwt);
            X509Certificate2 cert = new X509Certificate2(key, "notasecret");
            
            CspParameters cp = new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider",
                ((RSACryptoServiceProvider)cert.PrivateKey).CspKeyContainerInfo.KeyContainerName);
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider(cp);
            byte[] signature;
            signature = provider.SignData(buffer, "SHA256");
            Console.WriteLine("SIg :  " +  Base64UrlEncode(signature));

            string assertion = clearjwt + "." + Base64UrlEncode(signature);
            Console.WriteLine("CERT  : " + assertion);
            WebClient client = new WebClient();
            NameValueCollection formData = new NameValueCollection();
            formData["grant_type"] = "assertion";
            formData["assertion_type"] = "http://oauth.net/grant_type/jwt/1.0/bearer";
            //formData["access_type"] = "offline";
            formData["assertion"] = assertion;
            client.Headers["Content-type"] = "application/x-www-form-urlencoded";
         

            try
            {
                byte[] responseBytes = client.UploadValues("https://accounts.google.com/o/oauth2/token","POST", formData);
               // string Result = Encoding.UTF8.GetString(responseBytes).ToString().ToLower();
                string Result = Encoding.UTF8.GetString(responseBytes).ToString();
                string[] tokens = Result.Split(':');
                for (int i = 0; i < tokens.Length; i++)
                {
                    if (tokens[i].Contains("access_token"))
                        this.lauth_token = (tokens[i + 1].Split(',')[0].Replace("\"", ""));
                }
                Console.WriteLine(Result + "\n\n" + this.lauth_token);


                listBucket(key);
                
                //Console.ReadLine();
            }
            catch (UnauthorizedAccessException unExp)
            {
                Console.WriteLine("\nUnAuth Exception : " + unExp.Message + "\t" + unExp.StackTrace);
            }
            catch (WebException ex)
            {
                if (ex.Response != null)
                {
                    Stream receiveStream = ex.Response.GetResponseStream();
                    Encoding encode = System.Text.Encoding.GetEncoding("utf-8");
                    StreamReader readStream = new StreamReader(receiveStream, encode);
                    string pageContent = readStream.ReadToEnd();
                    Console.WriteLine("\nError: " + pageContent + "\t" + ex.StackTrace);
                }
                else
                    Console.Write(ex.Message + "\n" + ex.StackTrace);
            }
            Console.ReadLine();
        }
        private  long unix_timestamp()
        {
            //var networkDateTime = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds((long));
            //

            TimeSpan unix_time = (System.DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc));
            Console.WriteLine("\nNTP timing : " + unix_time.TotalSeconds);
            return (long)unix_time.TotalSeconds;
        }
        private  string Base64UrlEncode(byte[] ix)
        {
            var ret = Convert.ToBase64String(ix);
            ret = ret.Replace("=",String.Empty);
            ret = ret.Replace('+', '-');
            ret = ret.Replace('/', '_');
            return ret;
        }
        public String auth_token()
        {
            return this.lauth_token;
        }

        public void listBucket(string key)
        {
            try
            {
                //Authorization authorization = new Authorization(lauth_token);
                //Console.WriteLine("\n\n Authorization is : " + authorization.ProtectionRealm.Length.ToString());
                //Console.Read();

                byte[] buffer = Encoding.Default.GetBytes(lauth_token);

                X509Certificate2 cert = new X509Certificate2(key, "notasecret");

                CspParameters cp = new CspParameters(24,"Microsoft Enhanced RSA and AES Cryptographic Provider",
                    ((RSACryptoServiceProvider)cert.PrivateKey).CspKeyContainerInfo.KeyContainerName);
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider(cp);
                byte[] signature = provider.SignData(buffer, "SHA256");
                Console.WriteLine("SIGNATURE :  " + Base64UrlEncode(signature));
            //{                String jwt_header = "{\"Bearer " + lauth_token +"\"}";
            //    WebClient client = new WebClient();

            //    NameValueCollection formData = new NameValueCollection();
            //    formData["authorization"] = "delta-student-431";
            //    formData["maxResults"] = "5";
            //    formData["pageToken"] = lauth_token;
            //    formData["projection"] = "noAcl";
            //    formData["authorization"] = "Bearer";
            //    //formData["x-goog-project-id"] = "933144605699";
            //    Console.WriteLine(formData);
            //    client.Headers["Content-type"] = "application/x-www-form-urlencoded";

            //    byte[] responseBytes = client.UploadValues("https://www.googleapis.com/storage/v1beta2/b", "POST", formData);
            //    string Result = Encoding.UTF8.GetString(responseBytes).ToString().ToLower();
            //    //string[] tokens = Result.Split(':');
            //    //for (int i = 0; i < tokens.Length; i++)
            //    //{
            //    //    if (tokens[i].Contains("access_token"))
            //    //        this.lauth_token = (tokens[i + 1].Split(',')[0].Replace("\"", ""));
            //    //}
                
                
               var urlBuilder = new System.Text.StringBuilder();
                urlBuilder.Append("https://");
                urlBuilder.Append("www.googleapis.com");
                urlBuilder.Append("/storage/v1beta2/b");
                urlBuilder.Append("?project=delta-student-431");
                urlBuilder.Append("&maxResults=5");
                urlBuilder.Append("&access_token=" + lauth_token);
                //urlBuilder.Append("&token_type=Bearer");
                urlBuilder.Append("&projection=noAcl");


                Console.WriteLine("\nUrl  :  " + urlBuilder.ToString()); 

                string authToken = "Bearer " + lauth_token;
                var httpWebRequest = HttpWebRequest.Create("https://www.googleapis.com/storage/v1beta2/b?project=delta-student-431&maxResults=5&pageToken=" + lauth_token + "&projection=noAcl") as HttpWebRequest;
                //var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
                //httpWebRequest.CookieContainer = new CookieContainer();
                httpWebRequest.Headers.Add("Authorization", authToken);
                httpWebRequest.Method = "GET";
                //Console.WriteLine(
                var response = httpWebRequest.GetResponse();//.GetSafeResponse();

                 var responseText = response.GetResponseStream();//.GetResponseText();

                 StreamReader reader = new StreamReader(responseText);
                 string text = reader.ReadToEnd();

                 Console.WriteLine("\nBucket List is : " + text);
            }
            catch (Exception e)
            {
                Console.WriteLine("\n\nException is : " + e.Message + "\t " + e.StackTrace);
            }

        }
        public static string ComputeHash(string input, HashAlgorithm algorithm, Byte[] salt)
        {
            Byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            // Combine salt and input bytes
            Byte[] saltedInput = new Byte[salt.Length + inputBytes.Length];
            salt.CopyTo(saltedInput, 0);
            inputBytes.CopyTo(saltedInput, salt.Length);

            Byte[] hashedBytes = algorithm.ComputeHash(saltedInput);

            return BitConverter.ToString(hashedBytes);
        }

        static void GetMethod2(string client_id,string key)
        {

            //String ACTIVITY_ID = "z12gtjhq3qn2xxl2o224exwiqruvtda0i";
            String ACTIVITY_ID = client_id;

            Console.WriteLine("\nPlus API - Service Account");
            Console.WriteLine("==========================");

            String serviceAccountEmail = "933144605699-l5u74o4101bov3quvdk325hledk4hqjg@developer.gserviceaccount.com";

            var certificate = new X509Certificate2(key, "notasecret", X509KeyStorageFlags.Exportable);

            ServiceAccountCredential credential = new ServiceAccountCredential(
               new ServiceAccountCredential.Initializer(serviceAccountEmail)
               {
                   Scopes = new[] { PlusService.Scope.PlusMe }
               }.FromCertificate(certificate));

            // Create the service.
            var service = new PlusService(new BaseClientService.Initializer()
            {
                HttpClientInitializer = credential,
                ApplicationName = "Plus API Sample",
            });

            Activity activity = service.Activities.Get(ACTIVITY_ID).Execute();
            Console.WriteLine("  Activity: " + activity.Object.Content);
            Console.WriteLine("  Video: " + activity.Object.Attachments[0].Url);

            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();

        }
    }
}

