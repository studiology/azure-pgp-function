using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Collections.Concurrent;
using Microsoft.Azure.KeyVault.Models;
using System.Text;
using Microsoft.Azure.KeyVault;
using PgpCore;
using Microsoft.Azure.Services.AppAuthentication;
using System.Linq;

namespace RIC.Integration.Azure.Functions
{
    public static class FuncPGPEncrypt
    {
        private static readonly HttpClient client = new HttpClient();
        //private static ConcurrentDictionary<string, string> secrets = new ConcurrentDictionary<string, string>();

        [FunctionName( nameof( FuncPGPEncrypt ) )]
        public static async Task<IActionResult> RunAsync (
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
        HttpRequest req, ILogger log )
        {

            log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing start." );

            //Get the Base64 encoded public key.
            //string publicKeyBase64 = Environment.GetEnvironmentVariable("Base64PublicEncryptionKey");
            string publicKeySecretId = req.Headers["public-key-secret-id"];
            string blobstorageAccountSecID = req.Headers["blob-storageaccount-secret-id"];
            string blobstorageContainerSecID = req.Headers["blob-container-secret-id"];
            string sourceBlobFilename = req.Headers.ContainsKey("source-blob-filename") ? req.Headers["source-blob-filename"] : req.Headers["blob-filename"];
            string targetBlobFilename = req.Headers["target-blob-filename"];
            string targetBlobContainer= req.Headers["target-container"];

            string publicKeyBase64 = await GetPublicKeyAsync(publicKeySecretId, log);

            string blobstorageAccountConn = await GetPublicKeyAsync(blobstorageAccountSecID, log);
            string blobstorageContainer = !req.Headers.ContainsKey("blob-container-secret-id") 
                ? (string)req.Headers["source-container"] 
                : await GetPublicKeyAsync(blobstorageContainerSecID, log);

            long pgpsize = 0;

            try
            {

                //Extract the Json body out of request.
                //dynamic _requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                //var _requestObject = JsonConvert.DeserializeObject<ServiceRequest>(_requestBody as string);

                //Gets the Blob contents. Passing in the Container name and the file name.
                string _sFile = sourceBlobFilename; 
                string _dFile = targetBlobFilename; 
                string _sContainer = blobstorageContainer;
                string _dContainer = targetBlobContainer;
                string _fileContents = BlobHelper.GetBlob(blobstorageAccountConn, _sContainer, _sFile);

                //Convert the key to String
                byte[] data = Convert.FromBase64String(publicKeyBase64);
                string publicKey = Encoding.UTF8.GetString(data);

                //Encrypt the blob contents
                Stream encryptedData = await EncryptAsync(StringtoStream(_fileContents), publicKey);

                //Generate the pgp file with the correct file extension.
                _sFile = _sFile + ".pgp";
                //Write The encrypted file to the same Blob now. Extension is modified while file name remains the same. Later func activity will move it to SFTP destination.
                BlobHelper.WriteBlob( blobstorageAccountConn, _sContainer, _sFile, encryptedData );

                pgpsize = encryptedData.Length;
                //Data Factory requires Azure Function to response back in Json format, or JObject.
                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing commpleted. FileName : " + _sFile );

                return (ActionResult)new OkObjectResult( new { Status = "Success", Message = _sFile, PGPFilesize = pgpsize.ToString() } );
            }
            catch ( Exception exp )
            {
                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing failed. Exception : " + exp.ToString() );
                return new BadRequestObjectResult( new { Status = "Failure", Message = "funcPGPEncrypt Failed : " + exp.ToString() + "blobstorageAccountConn:" + blobstorageAccountConn + "publicKeySecretId" + publicKeySecretId + "blobstorageContainer" + blobstorageContainer } );
            }

        }



        //Helper function to convert String To Stream object.
        public static Stream StringtoStream ( string str )
        {
            byte[] byteArray = Encoding.UTF8.GetBytes(str);
            MemoryStream stream = new MemoryStream(byteArray);
            return stream;
        }

        private static async Task<string> GetPublicKeyAsync ( string secretIdentifier, ILogger log )
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
            var kvClient = new KeyVaultClient(authenticationCallback, client);

            SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);

            return secretBundle.Value;

            //if (!secrets.ContainsKey(secretIdentifier))
            //{
            //    secrets[secretIdentifier] = secretBundle.Value;
            //}

            //log.LogInformation($"Function {nameof(funcPGPEncrypt)} GetPublicKeyAsync commpleted. KeyID is : " + secretIdentifier + ", Key value is " + (string.IsNullOrWhiteSpace(secrets[secretIdentifier]) ? "NULL." : "Not NULL."));
            //return secrets[secretIdentifier];
        }

        private static async Task<Stream> EncryptAsync ( Stream inputStream, string publicKey )
        {
            using ( PGP pgp = new PGP() )
            {
                Stream outputStream = new MemoryStream();

                using ( inputStream )
                using ( Stream publicKeyStream = GenerateStreamFromString( publicKey ) )
                {
                    await pgp.EncryptStreamAsync( inputStream, outputStream, publicKeyStream, true, true );
                    outputStream.Seek( 0, SeekOrigin.Begin );
                    return outputStream;
                }
            }
        }

        private static Stream GenerateStreamFromString ( string s )
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write( s );
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }

    public static class FuncPGPDecrypt
    {
        private static readonly HttpClient clientDecrypt = new HttpClient();
        private static ConcurrentDictionary<string, string> secrectsDecrypt = new ConcurrentDictionary<string, string>();

        [FunctionName( nameof( FuncPGPDecrypt ) )]
        public static async Task<IActionResult> RunAsync ( [HttpTrigger( AuthorizationLevel.Function, "post", Route = null )] HttpRequest req,
                                                           ILogger log )
        {
            log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} processed a request." );

            string privateKeySecretId = req.Headers["privatekeysecretid"];
            string passPhraseSecretId = req.Headers["passphrasesecretid"];


            string blobstorageAccountSecID = req.Headers["blob-storageaccount-secret-id"];
            string blobstorageContainerSecID = req.Headers["blob-container-secret-id"];
            if ( privateKeySecretId == null )
            {
                return new BadRequestObjectResult( "Please pass a private key secret identifier on the query string" );
            }

            string blobStorageAccountConn = await GetFromKeyVaultAsync(blobstorageAccountSecID);
            string decryptingContainer = await GetFromKeyVaultAsync(blobstorageContainerSecID);

            string privateKey;
            string passPhrase = null;
            try
            {
                string baseprivateKey = await GetFromKeyVaultAsync(privateKeySecretId);

                //Convert the key to String
                byte[] data = Convert.FromBase64String(baseprivateKey);
                privateKey = Encoding.UTF8.GetString( data );

                if ( string.IsNullOrWhiteSpace( passPhraseSecretId ) == false )
                {
                    passPhrase = await GetFromKeyVaultAsync( passPhraseSecretId );
                }
            }
            catch ( KeyVaultErrorException e ) when ( e.Body.Error.Code == "SecretNotFound" )
            {
                return new NotFoundResult();
            }
            catch ( KeyVaultErrorException e ) when ( e.Body.Error.Code == "Forbidden" )
            {
                return new UnauthorizedResult();
            }

            log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} prepared variables." );
            string blobstorageFilename = req.Headers["blob-filename"];
            //Generate the pgp file with the correct file extension.
            string _fileName = blobstorageFilename;
            try
            {
                string fileext = Path.GetExtension(blobstorageFilename);
                if ( string.IsNullOrWhiteSpace( fileext ) )
                    _fileName = _fileName + ".CSV";
                else
                    _fileName = _fileName.Replace( fileext, ".CSV" );
            }
            catch
            {
                _fileName = _fileName + ".CSV";

            }

            try
            {
                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} reading blob." );
                string _fileContents = BlobHelper.GetBlob(blobStorageAccountConn, decryptingContainer, blobstorageFilename);

                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} decrypting blob." );

                if ( string.IsNullOrWhiteSpace( _fileContents ) )
                    log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} _fileContents is empty" );
                if ( string.IsNullOrWhiteSpace( privateKey ) )
                    log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} privateKey is empty" );
                if ( string.IsNullOrWhiteSpace( passPhrase ) )
                    log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} passPhrase is empty" );


                Stream decryptedData = await DecryptAsync(GenerateStreamFromString(_fileContents), privateKey, passPhrase);

                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} writing blob." );
                //Write The encrypted file to the same Blob now. Extension is modified while file name remains the same. Later func activity will move it to SFTP destination.
                BlobHelper.WriteBlob( blobStorageAccountConn, decryptingContainer, _fileName, decryptedData );


                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} processing commpleted. FileName : " + _fileName );

                return (ActionResult)new OkObjectResult( new { Status = "Success", Message = _fileName } );
            }
            catch ( Exception exp )
            {
                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPDecrypt )} processing failed. Exception : " + exp.ToString() );
                return new BadRequestObjectResult( new { Status = "Failure", Message = "funcPGPDecrypt Failed : " + exp.Message.ToString() } );
            }

            //return new OkObjectResult(decryptedData);
        }

        private static async Task<string> GetFromKeyVaultAsync ( string secretIdentifier )
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
            var kvClient = new KeyVaultClient(authenticationCallback, clientDecrypt);

            SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);
            //byte[] data = Convert.FromBase64String(secretBundle.Value);
            // Encoding.UTF8.GetString(data);

            return secretBundle.Value;

            // 
            //if (!secrectsDecrypt.ContainsKey(secretIdentifier))
            //{
            //    secrectsDecrypt[secretIdentifier] = secretBundle.Value;
            //}
            //return secrectsDecrypt[secretIdentifier];
        }

        private static async Task<Stream> DecryptAsync ( Stream inputStream, string privateKey, string passPhrase )
        {
            using ( PGP pgp = new PGP() )
            {
                Stream outputStream = new MemoryStream();

                using ( inputStream )
                using ( Stream privateKeyStream = GenerateStreamFromString( privateKey ) )
                {
                    await pgp.DecryptStreamAsync( inputStream, outputStream, privateKeyStream, passPhrase );
                    outputStream.Seek( 0, SeekOrigin.Begin );
                    return outputStream;
                }
            }
        }

        private static Stream GenerateStreamFromString ( string s )
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write( s );
            writer.Flush();
            stream.Position = 0;
            return stream;
        }


    }

    public static class PGPDecryptBlob
    {
        private static readonly HttpClient clientDecrypt = new HttpClient();
        private static ConcurrentDictionary<string, string> secrectsDecrypt = new ConcurrentDictionary<string, string>();

        [FunctionName( nameof( PGPDecryptBlob ) )]
        public static async Task<IActionResult> RunAsync (
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
        HttpRequest req, ILogger log )
        {
            log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} processed a request." );

            string privateKeySecretId = req.Headers["privatekeysecretid"];
            string passPhraseSecretId = req.Headers["passphrasesecretid"];


            string blobstorageAccountSecID = req.Headers["blob-storageaccount-secret-id"];
            string blobstorageContainerSecID = req.Headers["blob-container-secret-id"];
            string blobstorageFilename = req.Headers["blob-filename"];

            if ( privateKeySecretId == null )
            {
                return new BadRequestObjectResult( "Please pass a private key secret identifier on the query string" );
            }

            string blobStorageAccountConn = await GetFromKeyVaultAsync(blobstorageAccountSecID);
            string decryptingContainer = await GetFromKeyVaultAsync(blobstorageContainerSecID);

            string privateKey;
            string passPhrase = null;
            try
            {
                string baseprivateKey = await GetFromKeyVaultAsync(privateKeySecretId);

                //Convert the key to String
                byte[] data = Convert.FromBase64String(baseprivateKey);
                privateKey = Encoding.UTF8.GetString( data );

                if ( string.IsNullOrWhiteSpace( passPhraseSecretId ) == false )
                {
                    passPhrase = await GetFromKeyVaultAsync( passPhraseSecretId );
                }
            }
            catch ( KeyVaultErrorException e ) when ( e.Body.Error.Code == "SecretNotFound" )
            {
                return new NotFoundResult();
            }
            catch ( KeyVaultErrorException e ) when ( e.Body.Error.Code == "Forbidden" )
            {
                return new UnauthorizedResult();
            }

            log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} prepared variables." );
            //Generate the pgp file with the correct file extension.
            string _fileName = blobstorageFilename.Replace(".pgp","");


            try
            {
                log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} reading blob." );
                string _fileContents = BlobHelper.GetBlob(blobStorageAccountConn, decryptingContainer, blobstorageFilename);

                log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} decrypting blob." );

                if ( string.IsNullOrWhiteSpace( _fileContents ) )
                    log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} _fileContents is empty" );
                if ( string.IsNullOrWhiteSpace( privateKey ) )
                    log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} privateKey is empty" );
                if ( string.IsNullOrWhiteSpace( passPhrase ) )
                    log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} passPhrase is empty" );

                MemoryStream blobstream = new MemoryStream();
                await BlobHelper.GetBlobAsStream( blobStorageAccountConn, decryptingContainer, blobstorageFilename, blobstream );

                blobstream.Position = 0;
                Stream decryptedData = await DecryptAsync(blobstream, privateKey, passPhrase);

                log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} wrinting blob." );
                //Write The encrypted file to the same Blob now. Extension is modified while file name remains the same. Later func activity will move it to SFTP destination.
                BlobHelper.WriteBlob( blobStorageAccountConn, decryptingContainer, _fileName, decryptedData );


                log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} processing commpleted. FileName : " + _fileName );

                return (ActionResult)new OkObjectResult( new { Status = "Success", Message = _fileName } );
            }
            catch ( Exception exp )
            {
                log.LogInformation( $"C# HTTP trigger function {nameof( PGPDecryptBlob )} processing failed. Exception : " + exp.ToString() );
                return new BadRequestObjectResult( new { Status = "Failure", Message = "PGPDecryptBlob Failed : " + exp.Message.ToString() } );
            }

            //return new OkObjectResult(decryptedData);
        }

        private static async Task<string> GetFromKeyVaultAsync ( string secretIdentifier )
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
            var kvClient = new KeyVaultClient(authenticationCallback, clientDecrypt);

            SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);
            //byte[] data = Convert.FromBase64String(secretBundle.Value);
            // Encoding.UTF8.GetString(data);

            return secretBundle.Value;

            // 
            //if (!secrectsDecrypt.ContainsKey(secretIdentifier))
            //{
            //    secrectsDecrypt[secretIdentifier] = secretBundle.Value;
            //}
            //return secrectsDecrypt[secretIdentifier];
        }

        private static async Task<Stream> DecryptAsync ( Stream inputStream, string privateKey, string passPhrase )
        {
            using ( PGP pgp = new PGP() )
            {
                Stream outputStream = new MemoryStream();

                using ( inputStream )
                using ( Stream privateKeyStream = GenerateStreamFromString( privateKey ) )
                {
                    await pgp.DecryptStreamAsync( inputStream, outputStream, privateKeyStream, passPhrase );
                    outputStream.Seek( 0, SeekOrigin.Begin );
                    return outputStream;
                }
            }
        }

        private static Stream GenerateStreamFromString ( string s )
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write( s );
            writer.Flush();
            stream.Position = 0;
            return stream;
        }


    }

}
