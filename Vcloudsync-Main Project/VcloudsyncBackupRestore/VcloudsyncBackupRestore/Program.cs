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
//using Google.Apis.Auth.OAuth2.Flows;
////using Google.Apis.Auth.OAuth2.Requests;
////using Google.Apis.Auth.OAuth2.Responses;
//using Google.Apis.Auth.OAuth2.Web;
using Google.Apis.Authentication.OAuth2;
using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
//using Google.Apis.Books.v1;
//using Google.Apis.Books.v1.Data;
//using Google.Apis.Plus.v1;
//using Google.Apis.Plus.v1.Data;

using Google.Apis.Services;
//using Google.Apis.Util.Store;
using Google.Apis.Storage;
//using Google.Apis.Calendar.v3;
//using Google.Apis.Calendar.v3.Data;
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


namespace VcloudsyncBackupRestore
{
    class VcloudsyncBackupRestore
    {//  string client_Sec = "rMkXB6ZdyrYILKM9CE-KLqeb";
        string lauth_token;
     //   public static UserCredential credential;
        public static string filePath = @"M:\winrar-x64-500.exe";
        public static string objectName = "winrar-x64-500.exe";
        public static string bucketName = "trov004";
       // public static Google.Apis.Storage.v1beta2.StorageService service;
        static void Main(string[] args)
        {
            // Create the service.
           
            //listBucket();

            String client_id = "933144605699-l5u74o4101bov3quvdk325hledk4hqjg@developer.gserviceaccount.com";

            String key = @"M:\75b37f1819b9578a6cd622996e0dfe0fc0d43f91-privatekey.p12";

         

            Console.WriteLine(client_id + "<<<============================>>>" + key);
                VcloudsyncBackupRestore vc = new VcloudsyncBackupRestore(client_id, key);

               
                Console.Read();
         }
        public VcloudsyncBackupRestore(String client_id, String key)
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
            
                string Result = Encoding.UTF8.GetString(responseBytes).ToString();
                string[] tokens = Result.Split(':');
                for (int i = 0; i < tokens.Length; i++)
                {
                    if (tokens[i].Contains("access_token"))
                        this.lauth_token = (tokens[i + 1].Split(',')[0].Replace("\"", ""));
                }
                Console.WriteLine(Result + "\n\n" + this.lauth_token);


                //bucketInsertMethod(lauth_token, bucketName);

                bucketGetMethod(lauth_token, bucketName);

              //  bucketListMethod(key);

              //  bucketDeleteMethod(lauth_token, bucketName);

              //  objectInsertMethod(lauth_token, bucketName, objectName);

             //   objectMultipartInsertMethod(lauth_token, bucketName, objectName);

               // objectGetMethod(lauth_token, bucketName, objectName);

               

                //Console.WriteLine("\n\nINSERT SUCCESSFULLY");
                
                //Console.ReadLine();
            }
            catch (UnauthorizedAccessException unExp)
            {
                Console.WriteLine("UnAuth Exception : " + unExp.Message + "\t" + unExp.StackTrace);
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
        }


        private  long unix_timestamp()
        {
            TimeSpan unix_time = (System.DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc));
            Console.WriteLine("NTP timing : " + unix_time.TotalSeconds);
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

        public void bucketListMethod(string key)
        {
            try
            {

                byte[] buffer = Encoding.Default.GetBytes(lauth_token);

                X509Certificate2 cert = new X509Certificate2(key, "notasecret");

                CspParameters cp = new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider",
                    ((RSACryptoServiceProvider)cert.PrivateKey).CspKeyContainerInfo.KeyContainerName);
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider(cp);
                byte[] signature = provider.SignData(buffer, "SHA256");
                Console.WriteLine("SIg :  " + Base64UrlEncode(signature));               
                var urlBuilder = new System.Text.StringBuilder();
                urlBuilder.Append("https://");
                urlBuilder.Append("www.googleapis.com");
                urlBuilder.Append("/storage/v1beta2/b");
                urlBuilder.Append("?project=delta-student-431");
                urlBuilder.Append("&maxResults=5");
                urlBuilder.Append("&access_token=" + lauth_token);
                urlBuilder.Append("&projection=noAcl");


                Console.WriteLine("Url  :  " + urlBuilder.ToString()); 

                string authToken = "Bearer " + lauth_token;
                var httpWebRequest = HttpWebRequest.Create("https://www.googleapis.com/storage/v1beta2/b?project=delta-student-431&maxResults=5&pageToken=" + lauth_token + "&projection=noAcl") as HttpWebRequest;
                //var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
                //httpWebRequest.CookieContainer = new CookieContainer();
                httpWebRequest.Headers.Add("Authorization", authToken);
                httpWebRequest.Method = "GET";
                var response = httpWebRequest.GetResponse();//.GetSafeResponse();

                 var responseText = response.GetResponseStream();//.GetResponseText();

                 StreamReader reader = new StreamReader(responseText);
                 string text = reader.ReadToEnd();


                 //Google.Apis.Storage.v1beta2.BucketsResource.ListRequest listReq1 = service.Buckets.List("delta-student-431");
                 //Google.Apis.Storage.v1beta2.Data.Buckets bucketList1 = listReq1.Execute();
                 //IList<Google.Apis.Storage.v1beta2.Data.Bucket> bucketArray1 = bucketList1.Items;
                 //foreach (Google.Apis.Storage.v1beta2.Data.Bucket b3 in bucketArray1)
                 //{
                 //    Console.WriteLine("\n\n Bucket name :  " + b3.Name + "\t " + b3.Owner);
                 //}
                 Console.WriteLine("Bucket List is : " + text);
            }
            catch (Exception e)
            {
                Console.WriteLine("\n\n\n\nException is : " + e.Message + "\t " + e.StackTrace);
            }

        }



        public static string ComputeHash(string input, HashAlgorithm algorithm, Byte[] salt)
        {
            Byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            Byte[] saltedInput = new Byte[salt.Length + inputBytes.Length];
            salt.CopyTo(saltedInput, 0);
            inputBytes.CopyTo(saltedInput, salt.Length);

            Byte[] hashedBytes = algorithm.ComputeHash(saltedInput);

            return BitConverter.ToString(hashedBytes);
        }

        static void bucketInsertMethod(string lauth_token, string bucketName)
        {
            var urlBuilder = new System.Text.StringBuilder();
            urlBuilder.Append("https://");
            urlBuilder.Append("www.googleapis.com");
            urlBuilder.Append("/storage/v1beta2/b");
            urlBuilder.Append("?project=delta-student-431");

            string postData = "{\"name\":\"" + bucketName + "\",\"location\":\"US\"}";
            Encoding encoding = new UTF8Encoding();
            byte[] buff = encoding.GetBytes(postData);
            Console.WriteLine("Url  :  " + urlBuilder.ToString());

            string authToken = "Bearer " + lauth_token;

            var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
            httpWebRequest.Headers.Add("Authorization", authToken);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            Stream reqStream = httpWebRequest.GetRequestStream();
            reqStream.Write(buff, 0, buff.Length);

            var response = httpWebRequest.GetResponse();//.GetSafeResponse();

            var responseText = response.GetResponseStream();//.GetResponseText();

            StreamReader reader = new StreamReader(responseText);
            string text = reader.ReadToEnd();

            Console.WriteLine("Bucket inserted is : " + text);

        }


        static void bucketGetMethod(string lauth_token, string bucketName)
        {

          //  GET https://www.googleapis.com/storage/v1beta2/b/sample_bucket001?projection=full&fields=location&key={YOUR_API_KEY}

            var urlBuilder = new System.Text.StringBuilder();
            urlBuilder.Append("https://");
            urlBuilder.Append("www.googleapis.com");
            urlBuilder.Append("/storage/v1beta2/b/");
            urlBuilder.Append(bucketName);
            //urlBuilder.Append("project=delta-student-431/");
            //urlBuilder.Append("/projection=full");
            //urlBuilder.Append("?ifMetagenerationMatch=5");
            
            Console.WriteLine("Url  :  " + urlBuilder.ToString());

            string authToken = "Bearer " + lauth_token;

            var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
            httpWebRequest.Headers.Add("Authorization", authToken);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "GET";

            var response = httpWebRequest.GetResponse();//.GetSafeResponse();

            var responseText = response.GetResponseStream();//.GetResponseText();

            StreamReader reader = new StreamReader(responseText);
            string text = reader.ReadToEnd();

            Console.WriteLine("Bucket metadata using get is : " + text);

        }


        private void objectInsertMethod(string lauth_token, string bucketName, string objectName)
        {
            try
            {
                var urlBuilder = new System.Text.StringBuilder();
                urlBuilder.Append("https://");
                urlBuilder.Append("www.googleapis.com");
                urlBuilder.Append("/upload/storage/v1beta2/b/");
                urlBuilder.Append(bucketName);
                urlBuilder.Append("/o?uploadType=media&name=winrar-x64-500");

                //string postData = "{\"name\":\"" + bucName + "\",\"location\":\"US\"}";
                FileStream fStream = File.Open(filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
                Console.WriteLine("File length is : " + fStream.Length);
                Console.Read();
                Encoding encoding = new UTF8Encoding();
                //byte[] buff = encoding.GetBytes(postData);
                byte[] buff = new byte[fStream.Length];
                fStream.Read(buff, 0, buff.Length);
                fStream.Flush();
                fStream.Position = 0;
                Console.WriteLine("Url  :  " + urlBuilder.ToString());

                string authToken = "Bearer " + lauth_token;

                var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
                httpWebRequest.Headers.Add("Authorization", authToken);
                httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                httpWebRequest.Method = "POST";
                httpWebRequest.ContentLength = fStream.Length;

                Stream reqStream = httpWebRequest.GetRequestStream();
                reqStream.Write(buff, 0, buff.Length);

                var response = httpWebRequest.GetResponse();//.GetSafeResponse();

                var responseText = response.GetResponseStream();//.GetResponseText();

                StreamReader reader = new StreamReader(responseText);
                string text = reader.ReadToEnd();
                fStream.Close();
                Console.WriteLine("obj inserted is : " + text);
                
                Console.Read();
            }
            catch (WebException wex)
            {
                Console.WriteLine("\n\n\n Web Exception is : " + wex.Message + "\n" + wex.StackTrace);
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n\n\n Exception is  :  " + ex.Message + "\n" + ex.StackTrace);
            }
        }



        private void objectMultipartInsertMethod(string lauth_token, string bucketName, string objectName)
        {
            try
            {
                var urlBuilder = new System.Text.StringBuilder();
                urlBuilder.Append("https://");
                urlBuilder.Append("www.googleapis.com");
                urlBuilder.Append("/upload/storage/v1beta2/b/");
                urlBuilder.Append(bucketName);
                urlBuilder.Append("/o?uploadType=multipart&");
                urlBuilder.Append("name=" + objectName);

                //string postData = "{\"name\":\"" + bucName + "\",\"location\":\"US\"}";
                FileStream fStream = File.Open(filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
                Console.WriteLine("File length is : " + fStream.Length);
                Console.Read();
                Encoding encoding = new UTF8Encoding();
                //byte[] buff = encoding.GetBytes(postData);
                byte[] buff = new byte[fStream.Length];
                fStream.Read(buff, 0, buff.Length);
                fStream.Flush();
                fStream.Position = 0;
                Console.WriteLine("Url  :  " + urlBuilder.ToString());

                string authToken = "Bearer " + lauth_token;

                var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
                httpWebRequest.Headers.Add("Authorization", authToken);
                httpWebRequest.ContentType = "multipart / related; boundary = \"foo_bar_baz\" ";
                httpWebRequest.ContentLength = fStream.Length;
                httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                httpWebRequest.Method = "POST";
                httpWebRequest.ContentLength = fStream.Length;

                Stream reqStream = httpWebRequest.GetRequestStream();
                reqStream.Write(buff, 0, buff.Length);

                var response = httpWebRequest.GetResponse();//.GetSafeResponse();

                var responseText = response.GetResponseStream();//.GetResponseText();

                StreamReader reader = new StreamReader(responseText);
                string text = reader.ReadToEnd();
                fStream.Close();
                Console.WriteLine("obj inserted is : " + text);

                Console.Read();
            }
            catch (WebException wex)
            {
                Console.WriteLine("\n\n\n Web Exception is : " + wex.Message + "\n" + wex.StackTrace);
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n\n\n Exception is  :  " + ex.Message + "\n" + ex.StackTrace);
            }
        }



        private void objectGetMethod(string lauth_token, string bucketName, string objectName)
        {
            try
            {
                var urlBuilder = new System.Text.StringBuilder();
                urlBuilder.Append("https://www.googleapis.com/storage/v1beta2/b/");
                urlBuilder.Append(bucketName);
                urlBuilder.Append("/o/");
                urlBuilder.Append(objectName);

                FileStream fStream = File.Open(objectName, FileMode.OpenOrCreate, FileAccess.ReadWrite);


                //FileStream fStream = File.Open(@"M:\Lighthouse.jpg", FileMode.OpenOrCreate, FileAccess.ReadWrite);
                byte[] buff = new byte[561276];

                string authToken = "Bearer " + lauth_token;

                var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
                httpWebRequest.Headers.Add("Authorization", authToken);
                httpWebRequest.ContentType = "application/json";
                httpWebRequest.Method = "GET";

                var response = httpWebRequest.GetResponse();//.GetSafeResponse();

                var responseText = response.GetResponseStream();//.GetResponseText();

                StreamReader reader = new StreamReader(responseText);
                string text = reader.ReadToEnd();
                Console.WriteLine("obj download file  is : " + text);

                string[] tokens = text.Split(':');
                string mediaLine = "";

                for (int i = 0; i < tokens.Length; i++)
                {
                    if (tokens[i].Contains("mediaLink"))
                        mediaLine = (tokens[i + 2].Split(',')[0].Replace("\"", ""));
                }
                Console.WriteLine("\n\n\n\nhttps:" + mediaLine);
                Thread.Sleep(1000);
                //var httpWebRequest1 = HttpWebRequest.Create("https:" + mediaLine) as HttpWebRequest;
                var httpWebRequest1 = HttpWebRequest.Create("http://storage.googleapis.com/trov004/Lighthouse.jpg") as HttpWebRequest;
                httpWebRequest1.Headers.Add("Authorization", authToken);
                httpWebRequest1.ContentType = "image/jpeg";
                httpWebRequest1.Method = "GET";

                var response1 = httpWebRequest1.GetResponse();//.GetSafeResponse();

                var responseText1 = response1.GetResponseStream();//.GetResponseText();
                responseText1.Read(buff, 0, buff.Length);
                fStream.Write(buff, 0, buff.Length);
                fStream.Flush();
                fStream.Position = 0;
                fStream.Close();
                Console.Read();
            }
            catch (WebException wex)
            {
                Console.WriteLine("\n\n\n Web Exception is : " + wex.Message + "\n" + wex.StackTrace);
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n\n\n Exception is  :  " + ex.Message + "\n" + ex.StackTrace);
            }
        }

        private void bucketDeleteMethod(string lauth_token, string bucketName)
        {
            var urlBuilder = new System.Text.StringBuilder();
            urlBuilder.Append("https://");
            urlBuilder.Append("www.googleapis.com");
            urlBuilder.Append("/storage/v1beta2/b/");
            urlBuilder.Append(bucketName);

            Console.WriteLine("Url  :  " + urlBuilder.ToString());

            string authToken = "Bearer " + lauth_token;

            var httpWebRequest = HttpWebRequest.Create(urlBuilder.ToString()) as HttpWebRequest;
            httpWebRequest.Headers.Add("Authorization", authToken);
            httpWebRequest.ContentType = "application/stream";
            httpWebRequest.Method = "DELETE";

            var response = httpWebRequest.GetResponse();//.GetSafeResponse();

            var responseText = response.GetResponseStream();//.GetResponseText();

            StreamReader reader = new StreamReader(responseText);
            string text = reader.ReadToEnd();




            //// Create the service.
            //service = new Google.Apis.Storage.v1beta2.StorageService(new BaseClientService.Initializer()
            //{
            //    HttpClientInitializer = credential,
            //    ApplicationName = "storage API Sample",
            //});


            //Google.Apis.Storage.v1beta2.Data.Bucket b1 = new Google.Apis.Storage.v1beta2.Data.Bucket();
            //b1.Name = "trov";
            //b1.Location = "US";
            //b1.StorageClass = "DURABLE_REDUCED_AVAILABILITY";
            //Google.Apis.Storage.v1beta2.BucketsResource.DeleteRequest deleteReq = service.Buckets.Delete("trov004");
            //       string res = deleteReq.Execute();



                   Console.WriteLine("Bucket deleted is : " + text);
        }

        //static void GetMethod2(string client_id,string key)
        //{
        //    String ACTIVITY_ID = client_id;

        //    Console.WriteLine("Plus API - Service Account");
        //    Console.WriteLine("==========================");

        //    String serviceAccountEmail = "933144605699-l5u74o4101bov3quvdk325hledk4hqjg@developer.gserviceaccount.com";

        //    var certificate = new X509Certificate2(key, "notasecret", X509KeyStorageFlags.Exportable);

        //    ServiceAccountCredential credential = new ServiceAccountCredential(
        //       new ServiceAccountCredential.Initializer(serviceAccountEmail)
        //       {
        //           Scopes = new[] { Google.Apis.Storage.v1beta2.StorageService.Scope.DevstorageFullControl }
        //       }.FromCertificate(certificate));

        //    // Create the service.
        //    var service = new Google.Apis.Storage.v1beta2.StorageService(new BaseClientService.Initializer()
        //    {
        //        HttpClientInitializer = credential,
        //        ApplicationName = "storage API Sample",
        //    });


        //    //Google.Apis.Storage.v1beta2.Data.Bucket b1 = new Google.Apis.Storage.v1beta2.Data.Bucket();
        //    //b1.Name = "trov";
        //    //b1.Location = "US";
        //    //b1.StorageClass = "DURABLE_REDUCED_AVAILABILITY";

        //    //Google.Apis.Storage.v1beta2.BucketsResource.InsertRequest insertReq = service.Buckets.Insert(b1, "delta-student-431");
        //    //Google.Apis.Storage.v1beta2.Data.Bucket b2 = insertReq.Execute();


        //    //Google.Apis.Storage.v1beta2.BucketsResource.ListRequest listReq1 = service.Buckets.List("delta-student-431");
        //    //Google.Apis.Storage.v1beta2.Data.Buckets bucketList1 = listReq1.Execute();
        //    //IList<Google.Apis.Storage.v1beta2.Data.Bucket> bucketArray1 = bucketList1.Items;
        //    //foreach (Google.Apis.Storage.v1beta2.Data.Bucket b3 in bucketArray1)
        //    //{
        //    //    Console.WriteLine("\n\n Bucket name :  " + b3.Name);
        //    //}


        //    Console.WriteLine("Press any key to continue...");
        //    Console.ReadKey();

        //}
    }
}
