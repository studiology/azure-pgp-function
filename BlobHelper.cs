using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;

using System;
using System.IO;
using System.Threading.Tasks;

namespace RIC.Integration.Azure.Functions
{
    internal class BlobHelper
    {
        //Helper method to read the contents of the Blob
        public static string GetBlob ( string blobstorageAccountConn, string containerName, string fileName )
        {
            string connectionString = blobstorageAccountConn;

            // Setup the connection to the storage account
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(connectionString);

            // Connect to the blob storage
            CloudBlobClient serviceClient = storageAccount.CreateCloudBlobClient();
            // Connect to the blob container
            CloudBlobContainer container = serviceClient.GetContainerReference($"{containerName}");
            // Connect to the blob file
            CloudBlockBlob blob = container.GetBlockBlobReference($"{fileName}");
            // Get the blob file as text
            string contents = blob.DownloadTextAsync().Result;

            return contents;
        }

        public static async Task GetBlobAsStream ( string blobstorageAccountConn, string containerName, string fileName, Stream targetStream )
        {
            string connectionString = blobstorageAccountConn;

            // Setup the connection to the storage account
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(connectionString);

            // Connect to the blob storage
            CloudBlobClient serviceClient = storageAccount.CreateCloudBlobClient();
            // Connect to the blob container
            CloudBlobContainer container = serviceClient.GetContainerReference($"{containerName}");
            // Connect to the blob file
            CloudBlockBlob blob = container.GetBlockBlobReference($"{fileName}");
            // Get the blob file as text
            await blob.DownloadToStreamAsync( targetStream );
        }

        //Helper method to write the file to Blob
        public static void WriteBlob ( string blobstorageAccountConn, string containerName, string fileName, Stream fileContents )
        {
            string connectionString = blobstorageAccountConn;

            // Setup the connection to the storage account
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(connectionString);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference(containerName);

            // TODO: Add boolean CreateContainerIfNecessary option
            //container.CreateIfNotExists();

            CloudBlockBlob blob = container.GetBlockBlobReference(fileName);

            var options = new BlobRequestOptions()
            {
                //SingleBlobUploadThresholdInBytes = 1024 * 1024, //1MB, the minimum
                ParallelOperationThreadCount = 8,
                DisableContentMD5Validation = true,
                StoreBlobContentMD5 = false,
                ServerTimeout = TimeSpan.FromMinutes(10)
            };
            blob.StreamWriteSizeInBytes = 10 * 1024 * 1024; //10M

            blob.UploadFromStreamAsync( fileContents, null, options, null );
        }


    }

}
