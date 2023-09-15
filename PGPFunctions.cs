using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Http;
using System.Collections.Concurrent;
using Microsoft.Azure.KeyVault.Models;
using System.Text;
using Microsoft.Azure.KeyVault;
using PgpCore;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.AspNetCore.Http.Internal;


namespace RIC.Integration.Azure.Functions
{
    public static class LAPGPDecrypt
    {
        private static readonly HttpClient clientDecrypt = new HttpClient();
        private static ConcurrentDictionary<string, string> secrectsDecrypt = new ConcurrentDictionary<string, string>();

        [FunctionName(nameof(LAPGPDecrypt))]
        public static async Task<IActionResult> RunAsync(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
        HttpRequest req, ILogger log)
        {
            log.LogInformation($"C# HTTP trigger function {nameof(LAPGPDecrypt)} processed a request.");

            string privateKeySecretId = req.Headers["privatekeysecretid"];
            string passPhraseSecretId = req.Headers["passphrasesecretid"];

            if (privateKeySecretId == null)
            {
                return new BadRequestObjectResult("Please pass a private key secret identifier on the query string");
            }

            string privateKey;
            string passPhrase = null;
            try
            {
                string baseprivateKey = await GetFromKeyVaultAsync(privateKeySecretId);
                byte[] data = Convert.FromBase64String(baseprivateKey);
                privateKey = Encoding.UTF8.GetString(data);
                if (string.IsNullOrWhiteSpace(passPhraseSecretId) == false)
                {
                    passPhrase = await GetFromKeyVaultAsync(passPhraseSecretId);
                }
            }
            catch (KeyVaultErrorException e) when (e.Body.Error.Code == "SecretNotFound")
            {
                return new NotFoundResult();
            }
            catch (KeyVaultErrorException e) when (e.Body.Error.Code == "Forbidden")
            {
                return new UnauthorizedResult();
            }

            log.LogInformation($"C# HTTP trigger function {nameof(LAPGPDecrypt)} decrypting a request.");
            Stream decryptedData = await DecryptAsync(req.Body, privateKey, passPhrase);

            log.LogInformation($"C# HTTP trigger function {nameof(LAPGPDecrypt)} decrypted a request.");

            return new OkObjectResult(decryptedData);
        }

        private static async Task<string> GetFromKeyVaultAsync(string secretIdentifier)
        {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
                var kvClient = new KeyVaultClient(authenticationCallback, clientDecrypt);

                SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);
            //byte[] data = Convert.FromBase64String(secretBundle.Value);
            // Encoding.UTF8.GetString(data);

            return secretBundle.Value;
            //if (!secrectsDecrypt.ContainsKey(secretIdentifier))
            //{
            //    secrectsDecrypt[secretIdentifier] = secretBundle.Value;
            //}
            //return secrectsDecrypt[secretIdentifier];
        }

        [Obsolete]
        private static async Task<Stream> DecryptAsync(Stream inputStream, string privateKey, string passPhrase)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();

                using (inputStream)
                using (Stream privateKeyStream = GenerateStreamFromString(privateKey))
                {
                    await pgp.DecryptStreamAsync(inputStream, outputStream, privateKeyStream, passPhrase);
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
        }

        private static Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }

    public static class LAPGPEncrypt
    {
        private static readonly HttpClient Encryptclient = new HttpClient();
        private static ConcurrentDictionary<string, string> secretsencrypt = new ConcurrentDictionary<string, string>();


        [FunctionName(nameof(LAPGPEncrypt))]
        public static async Task<IActionResult> RunAsync(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
        HttpRequest req, ILogger log)
        {
            log.LogInformation($"C# HTTP trigger function {nameof(LAPGPEncrypt)} processed a request.");

            string publicKeyBase64 = req.Headers["public-key"];
            string publicKeyEnvironmentVariable = req.Headers["public-key-environment-variable"];
            string publicKeySecretId = req.Headers["public-key-secret-id"];

            if (publicKeyBase64 == null && publicKeyEnvironmentVariable == null && publicKeySecretId == null)
            {
                return new BadRequestObjectResult("Please pass a base64 encoded public key, an environment variable name, or a key vault secret identifier on the query string");
            }

            if (publicKeyBase64 == null && publicKeyEnvironmentVariable != null)
            {
                publicKeyBase64 = Environment.GetEnvironmentVariable(publicKeyEnvironmentVariable);
            }

            if (publicKeyBase64 == null && publicKeySecretId != null)
            {
                try
                {
                    publicKeyBase64 = await GetPublicKeyAsync(publicKeySecretId);
                }
                catch (KeyVaultErrorException e) when (e.Body.Error.Code == "SecretNotFound")
                {
                    return new NotFoundResult();
                }
                catch (KeyVaultErrorException e) when (e.Body.Error.Code == "Forbidden")
                {
                    return new UnauthorizedResult();
                }
            }
            byte[] data = Convert.FromBase64String(publicKeyBase64);
            string publicKey = Encoding.UTF8.GetString(data);
            req.EnableRewind(); //Make RequestBody Stream seekable
            Stream encryptedData = await EncryptAsync(req.Body, publicKey);

            return new OkObjectResult(encryptedData);
        }

        private static async Task<string> GetPublicKeyAsync(string secretIdentifier)
        {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
                var kvClient = new KeyVaultClient(authenticationCallback, Encryptclient);

                SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);

            return secretBundle.Value;
            //if (!secretsencrypt.ContainsKey(secretIdentifier))
            //{
            //    secretsencrypt[secretIdentifier] = secretBundle.Value;
            //}
            //return secretsencrypt[secretIdentifier];
        }

        [Obsolete]
        private static async Task<Stream> EncryptAsync(Stream inputStream, string publicKey)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();

                using (inputStream)
                using (Stream publicKeyStream = GenerateStreamFromString(publicKey))
                {
                    await pgp.EncryptStreamAsync(inputStream, outputStream, publicKeyStream, true, true);
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
        }

        private static Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }
}
