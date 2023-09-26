using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

using PgpCore;

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace RIC.Integration.Azure.Functions
{
    public static class FuncPGPEncrypt
    {
        private static readonly HttpClient client = new HttpClient();
        //private static ConcurrentDictionary<string, string> secrets = new ConcurrentDictionary<string, string>();

        [FunctionName( nameof( FuncPGPEncrypt ) )]
        [Obsolete]
        public static async Task<IActionResult> RunAsync (
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
        HttpRequest req, ILogger log )
        {

            log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing start." );

            //Get the Base64 encoded public key.
            //string publicKeyBase64 = Environment.GetEnvironmentVariable("Base64PublicEncryptionKey");
            string publicKeySecretId         = (string)req.Headers["public-key-secret-id"];
            string blobstorageAccountSecID   = (string)req.Headers["blob-storageaccount-secret-id"];
            string blobstorageContainerSecID = (string)req.Headers["blob-container-secret-id"];
            string sourceBlobFilename        = req.Headers.ContainsKey("source-blob-filename") ? (string)req.Headers["source-blob-filename"] : (string)req.Headers["blob-filename"];
            string targetBlobContainer       = (string)req.Headers["target-container"];
            string targetBlobFilename        = !string.IsNullOrWhiteSpace( req.Headers["target-blob-filename"] ) ? (string)req.Headers["target-blob-filename"] : sourceBlobFilename;
            try
            {
                string publicKeyBase64 = await GetSecretAsync( publicKeySecretId, log );
                string blobstorageAccountConn = await GetSecretAsync( blobstorageAccountSecID, log );
                string blobstorageContainer = (string)req.Headers?["source-container"] ?? await GetSecretAsync( blobstorageContainerSecID, log );


                //Gets the Blob contents. Passing in the Container name and the file name.
                string _sFile = sourceBlobFilename;
                string _dFile = targetBlobFilename;
                string _sContainer = blobstorageContainer;
                string _dContainer = string.IsNullOrWhiteSpace(targetBlobContainer) ? _sContainer : targetBlobContainer;
                string _fileContents = BlobHelper.GetBlob(blobstorageAccountConn, _sContainer, _sFile);

                //Convert the key to String
                byte[] data = Convert.FromBase64String(publicKeyBase64);
                string publicKey = Encoding.UTF8.GetString(data);

                //Encrypt the blob contents
                Stream encryptedData = await EncryptAsync(StringtoStream(_fileContents), publicKey);

                //Generate the pgp file with the correct file extension.
                _sFile += ".pgp";
                //Write The encrypted file to the same Blob now. Extension is modified while file name remains the same. Later func activity will move it to SFTP destination.
                BlobHelper.WriteBlob( blobstorageAccountConn, _dContainer, _dFile, encryptedData );

                //Data Factory requires Azure Function to response back in Json format, or JObject.
                log.LogInformation( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing commpleted. FileName : " + _dFile );

                return new OkObjectResult( (Status: "Success", Message: _dFile, PGPFilesize: encryptedData.Length) );
            }
            catch ( KeyVaultErrorException e ) when ( e.Body.Error.Code == "SecretNotFound" )
            {
                log.LogError( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing failed. Exception : {e}" );
                return new NotFoundResult();
            }
            catch ( KeyVaultErrorException e ) when ( e.Body.Error.Code == "Forbidden" )
            {
                log.LogError( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing failed. Exception : {e}" );
                return new UnauthorizedResult();
            }
            catch ( Exception e )
            {
                log.LogError( $"C# HTTP trigger function {nameof( FuncPGPEncrypt )} processing failed. Exception : {e}" );
                return new BadRequestObjectResult( (Status: "Failure", Message: $"Failed : {e.Message}. ") );
            }

        }



        //Helper function to convert String To Stream object.
        public static Stream StringtoStream ( string str )
        {
            byte[] byteArray = Encoding.UTF8.GetBytes(str);
            MemoryStream stream = new MemoryStream(byteArray);
            return stream;
        }

        private static async Task<string> GetSecretAsync ( string secretIdentifier, ILogger log )
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
            var kvClient = new KeyVaultClient(authenticationCallback, client);

            log.LogDebug( $"looking up secretIdentifier {secretIdentifier} in Key Vault" );
            SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);
            return secretBundle.Value;
        }

        // TODO: Replace with new method
        [Obsolete]
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
                if ( fileext.Equals( ".pgp", comparisonType: StringComparison.InvariantCultureIgnoreCase )
                  || fileext.Equals( ".gpg", comparisonType: StringComparison.InvariantCultureIgnoreCase ) )
                {
                    _fileName = _fileName.Remove( startIndex: _fileName.LastIndexOf('.') );
                }
            }
            catch
            {
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


                Stream decryptedData = await DecryptAsync(GenerateStreamFromString(_fileContents),
                                                          GenerateStreamFromString(privateKey),
                                                          passPhrase);

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

        [Obsolete]
        private static async Task<Stream> DecryptAsync ( Stream inputStream, string privateKey, string passPhrase )
        {
            using ( PGP pgp = new PGP() )
            {
                Stream outputStream = new MemoryStream();

                using ( inputStream )
                using ( Stream privateKeyStream = GenerateStreamFromString( privateKey ) )
                {
                    _ = await pgp.DecryptStreamAsync( inputStream, outputStream, privateKeyStream, passPhrase );
                    outputStream.Seek( 0, SeekOrigin.Begin );
                    return outputStream;
                }
            }
        }
        private static async Task<Stream> DecryptAsync ( Stream inputStream, Stream privateKeyStream, string passPhrase )
        {
            using ( privateKeyStream )
            {
                EncryptionKeys encryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);
                using ( PGP pgp = new PGP( encryptionKeys ) )
                {
                    Stream outputStream = new MemoryStream();

                    using ( inputStream )
                    {
                        _ = await pgp.DecryptStreamAsync( inputStream, outputStream );
                        outputStream.Seek( 0, SeekOrigin.Begin );
                        return outputStream;
                    }
                }
            }
        }

        private static async Task<Stream> DecryptAsync ( Stream inputStream, EncryptionKeys encryptionKeys )
        {
            using ( PGP pgp = new PGP( encryptionKeys ) )
            {
                Stream outputStream = new MemoryStream();

                using ( inputStream )
                {
                    _ = await pgp.DecryptStreamAsync( inputStream, outputStream );
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
        [Obsolete]
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

        [Obsolete]
        private static async Task<Stream> DecryptAsync ( Stream inputStream, string privateKey, string passPhrase )
        {
            using ( PGP pgp = new PGP() )
            {
                Stream outputStream = new MemoryStream();

                using ( inputStream )
                using ( Stream privateKeyStream = GenerateStreamFromString( privateKey ) )
                {
                    _ = await pgp.DecryptStreamAsync( inputStream, outputStream, privateKeyStream, passPhrase );
                    _ = outputStream.Seek( 0, SeekOrigin.Begin );
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
