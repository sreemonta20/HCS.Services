using HCS.Security.Models.Configuration;
using HCS.Security.Service;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Ocsp;
using System.Security.Cryptography;
using System.Text;

namespace HCS.Security.Helper
{
    //public class EncryptDecryptMiddleware : DelegatingHandler
    //{

    //    private readonly AppSettings _appSettings;
    //    private readonly byte[] _key;
    //    private readonly byte[] _iv;

    //    public EncryptDecryptMiddleware(IOptions<AppSettings> appSettings)
    //    {
    //        _appSettings = appSettings.Value;
    //        _key = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //        _iv = Encoding.UTF8.GetBytes(_appSettings.EncryptIV);

    //    }

    //    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    //    {
    //        // Encrypt the request body
    //        if (request.Method == HttpMethod.Post && request.Content != null)
    //        {
    //            byte[] encryptedRequestBody = await EncryptRequestBody(request.Content);
    //            request.Content = new ByteArrayContent(encryptedRequestBody);
    //        }

    //        // Decrypt the response body
    //        HttpResponseMessage response = await base.SendAsync(request, cancellationToken);
    //        if (response.Content != null)
    //        {
    //            byte[] decryptedResponseBody = await DecryptResponseBody(response.Content);
    //            response.Content = new ByteArrayContent(decryptedResponseBody);
    //        }

    //        return response;
    //    }

    //    private async Task<byte[]> EncryptRequestBody(HttpContent content)
    //    {
    //        byte[] requestBodyBytes = await content.ReadAsByteArrayAsync();
    //        using (Aes aes = Aes.Create())
    //        {
    //            aes.Key = _key;
    //            aes.IV = _iv;

    //            using (MemoryStream ms = new MemoryStream())
    //            {
    //                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
    //                {
    //                    await cs.WriteAsync(requestBodyBytes, 0, requestBodyBytes.Length);
    //                }
    //                return ms.ToArray();
    //            }
    //        }
    //    }

    //    private async Task<byte[]> DecryptResponseBody(HttpContent content)
    //    {
    //        byte[] responseBodyBytes = await content.ReadAsByteArrayAsync();
    //        using (Aes aes = Aes.Create())
    //        {
    //            aes.Key = _key;
    //            aes.IV = _iv;

    //            using (MemoryStream ms = new MemoryStream())
    //            {
    //                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
    //                {
    //                    await cs.WriteAsync(responseBodyBytes, 0, responseBodyBytes.Length);
    //                }
    //                return ms.ToArray();
    //            }
    //        }
    //    }

    //    private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] iv)
    //    {
    //        using (var aesAlg = Aes.Create())
    //        {
    //            aesAlg.Key = key;
    //            aesAlg.IV = iv;

    //            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

    //            using (var msDecrypt = new MemoryStream(cipherText))
    //            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
    //            using (var srDecrypt = new StreamReader(csDecrypt))
    //            {
    //                return srDecrypt.ReadToEnd();
    //            }
    //        }
    //    }

    //    public string Encrypt(string plainText)
    //    {
    //        using var aes = Aes.Create();
    //        aes.Key = _key;
    //        aes.IV = _iv;

    //        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

    //        using var msEncrypt = new MemoryStream();
    //        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
    //        using (var swEncrypt = new StreamWriter(csEncrypt))
    //        {
    //            swEncrypt.Write(plainText);
    //        }

    //        var encrypted = msEncrypt.ToArray();

    //        return Convert.ToBase64String(encrypted);
    //    }
    //}

    //public class EncryptDecryptMiddleware
    //{
    //    private readonly RequestDelegate _next;
    //    private readonly AppSettings _appSettings;
    //    private readonly byte[] _key;
    //    private readonly byte[] _iv;

    //    public EncryptDecryptMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
    //    {
    //        _next = next;
    //        _appSettings = appSettings.Value;
    //        _key = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //        _iv = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //    }

    //    public async Task InvokeAsync(HttpContext context)
    //    {
    //        // Read the request body
    //        var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();

    //        // Decrypt the request body using AES
    //        var decryptedRequestBody = AESDecrypt(requestBody, _key);

    //        // Replace the request body with the decrypted version
    //        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(decryptedRequestBody));

    //        // Call the next middleware in the pipeline
    //        await _next(context);
    //    }

    //    private static string AESDecrypt(string cipherText, byte[] key)
    //    {
    //        var aes = Aes.Create();
    //        aes.Key = key;
    //        aes.Mode = CipherMode.CBC;
    //        aes.Padding = PaddingMode.PKCS7;
    //        var cipherBytes = Convert.FromBase64String(cipherText);
    //        var iv = cipherBytes.Take(aes.BlockSize / 8).ToArray();
    //        var cipherTextBytes = cipherBytes.Skip(aes.BlockSize / 8).ToArray();
    //        using var ms = new MemoryStream(cipherTextBytes);
    //        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
    //        using var sr = new StreamReader(cs);
    //        return sr.ReadToEnd();
    //    }
    //}

    //public class EncryptDecryptMiddleware : IMiddleware
    //{
    //    private readonly IEncryptDecryptService _encryptionService;

    //    public EncryptDecryptMiddleware(IEncryptDecryptService encryptionService)
    //    {
    //        _encryptionService = encryptionService;
    //    }

    //    //public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    //    //{
    //    //    if (context.Request.Path.StartsWithSegments("/login"))
    //    //    {
    //    //        string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
    //    //        var decryptedRequestBody = _encryptionService.Decrypt(requestBody);
    //    //        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(decryptedRequestBody));
    //    //        context.Request.Headers.Remove("Content-Length");
    //    //        context.Request.ContentLength = context.Request.Body.Length;
    //    //    }

    //    //    await next(context);
    //    //}

    //    public async Task InvokeAsync(HttpContext httpContext, RequestDelegate next)
    //    {
    //        httpContext.Response.Body = _encryptionService.EncryptStream(httpContext.Response.Body);
    //        httpContext.Request.Body = _encryptionService.DecryptStream(httpContext.Request.Body);
    //        if (httpContext.Request.QueryString.HasValue)
    //        {
    //            string decryptedString = _encryptionService.Decrypt(httpContext.Request.QueryString.Value.Substring(1));
    //            httpContext.Request.QueryString = new QueryString($"?{decryptedString}");
    //        }
    //        await next(httpContext);
    //        await httpContext.Request.Body.DisposeAsync();
    //        await httpContext.Response.Body.DisposeAsync();
    //    }

    //public class EncryptDecryptMiddleware: IMiddleware
    //{
    //    private readonly AppSettings _appSettings;
    //    private readonly byte[] _key;
    //    private readonly byte[] _iv;

    //    public EncryptDecryptMiddleware(IOptions<AppSettings> appSettings)
    //    {
    //        _appSettings = appSettings.Value;
    //        _key = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //        _iv = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //    }

    //    //public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    //    //{
    //    //    if (context.Request.Path.StartsWithSegments("/login"))
    //    //    {
    //    //        string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
    //    //        var decryptedRequestBody = _encryptionService.Decrypt(requestBody);
    //    //        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(decryptedRequestBody));
    //    //        context.Request.Headers.Remove("Content-Length");
    //    //        context.Request.ContentLength = context.Request.Body.Length;
    //    //    }

    //    //    await next(context);
    //    //}

    //    public async Task InvokeAsync(HttpContext httpContext, RequestDelegate next)
    //    {
    //        httpContext.Response.Body = EncryptStream(httpContext.Response.Body);
    //        httpContext.Request.Body = DecryptStream(httpContext.Request.Body);
    //        if (httpContext.Request.QueryString.HasValue)
    //        {
    //            string decryptedString = Decrypt(httpContext.Request.QueryString.Value.Substring(1));
    //            httpContext.Request.QueryString = new QueryString($"?{decryptedString}");
    //        }
    //        await next(httpContext);
    //        await httpContext.Request.Body.DisposeAsync();
    //        await httpContext.Response.Body.DisposeAsync();
    //    }


    //    public string Encrypt(string plainText)
    //    {
    //        using var aes = Aes.Create();
    //        aes.Key = _key;
    //        aes.IV = _iv;

    //        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

    //        using var msEncrypt = new MemoryStream();
    //        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
    //        using (var swEncrypt = new StreamWriter(csEncrypt))
    //        {
    //            swEncrypt.Write(plainText);
    //        }

    //        var encrypted = msEncrypt.ToArray();

    //        return Convert.ToBase64String(encrypted);
    //    }

    //    public string Decrypt(string cipherText)
    //    {
    //        var cipherBytes = Convert.FromBase64String(cipherText);

    //        using var aes = Aes.Create();
    //        aes.Key = _key;
    //        aes.IV = _iv;

    //        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

    //        using var msDecrypt = new MemoryStream(cipherBytes);
    //        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
    //        using var srDecrypt = new StreamReader(csDecrypt);

    //        return srDecrypt.ReadToEnd();
    //    }

    //    public Stream DecryptStream(Stream cipherStream)
    //    {
    //        Aes aes = GetEncryptionAlgorithm();

    //        FromBase64Transform base64Transform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces);
    //        CryptoStream base64DecodedStream = new CryptoStream(cipherStream, base64Transform, CryptoStreamMode.Read);
    //        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
    //        CryptoStream decryptedStream = new CryptoStream(base64DecodedStream, decryptor, CryptoStreamMode.Read);
    //        return decryptedStream;
    //    }

    //    public CryptoStream EncryptStream(Stream responseStream)
    //    {
    //        Aes aes = GetEncryptionAlgorithm();

    //        ToBase64Transform base64Transform = new ToBase64Transform();
    //        CryptoStream base64EncodedStream = new CryptoStream(responseStream, base64Transform, CryptoStreamMode.Write);
    //        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
    //        CryptoStream cryptoStream = new CryptoStream(base64EncodedStream, encryptor, CryptoStreamMode.Write);

    //        return cryptoStream;
    //    }

    //    private Aes GetEncryptionAlgorithm()
    //    {
    //        Aes aes = Aes.Create();
    //        aes.Key = _key;
    //        aes.IV = _iv;

    //        return aes;
    //    }
    //}

    //public class EncryptDecryptMiddleware : DelegatingHandler
    //{
    //    private readonly AppSettings _appSettings;
    //    //private readonly byte[] _key;
    //    //private readonly byte[] _iv;
    //    public EncryptDecryptMiddleware(IOptions<AppSettings> appSettings)
    //    {
    //        _appSettings = appSettings.Value;
    //        //_key = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //        //_iv = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //    }

    //    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    //    {
    //        // Decrypt the request body
    //        var encryptedRequestBody = await request.Content.ReadAsByteArrayAsync();
    //        var decryptedRequestBody = DecryptAes256(encryptedRequestBody);
    //        request.Content = new ByteArrayContent(decryptedRequestBody);

    //        // Call the inner handler to send the request
    //        var response = await base.SendAsync(request, cancellationToken);

    //        // Encrypt the response body
    //        var encryptedResponseBody = await response.Content.ReadAsByteArrayAsync();
    //        var decryptedResponseBody = EncryptAes256(encryptedResponseBody);
    //        response.Content = new ByteArrayContent(decryptedResponseBody);

    //        return response;
    //    }

    //    private byte[] DecryptAes256(byte[] encryptedData)
    //    {
    //        // Replace with your own key and IV values
    //        var key = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //        var iv = Encoding.UTF8.GetBytes(_appSettings.EncryptIV);

    //        using (var aes = Aes.Create())
    //        {
    //            aes.Key = key;
    //            aes.IV = iv;
    //            aes.Mode = CipherMode.CBC;
    //            aes.Padding = PaddingMode.PKCS7;

    //            using (var decryptor = aes.CreateDecryptor())
    //            using (var msDecrypt = new MemoryStream(encryptedData))
    //            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
    //            using (var srDecrypt = new StreamReader(csDecrypt))
    //            {
    //                var decrypted = srDecrypt.ReadToEnd();
    //                return Encoding.UTF8.GetBytes(decrypted);
    //            }
    //        }
    //    }

    //    private byte[] EncryptAes256(byte[] plainText)
    //    {
    //        // Replace with your own key and IV values
    //        var key = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
    //        var iv = Encoding.UTF8.GetBytes(_appSettings.EncryptIV);

    //        using (var aes = Aes.Create())
    //        {
    //            aes.Key = key;
    //            aes.IV = iv;
    //            aes.Mode = CipherMode.CBC;
    //            aes.Padding = PaddingMode.PKCS7;

    //            using (var encryptor = aes.CreateEncryptor())
    //            using (var msEncrypt = new MemoryStream())
    //            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
    //            {
    //                csEncrypt.Write(plainText, 0, plainText.Length);
    //                csEncrypt.FlushFinalBlock();
    //                return msEncrypt.ToArray();
    //            }
    //        }
    //    }
    //}

    public class EncryptDecryptMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;
        public EncryptDecryptMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
        {
            _next = next;
            _appSettings = appSettings.Value;
        }
        // Whenever we call any action method then call this before call the action method
        public async Task Invoke(HttpContext httpContext)
        {
            //httpContext.Request.EnableRewind();
            httpContext.Request.EnableBuffering();
            List<string> excludeURL = GetExcludeURLList();
            if (!excludeURL.Contains(httpContext.Request.Path.Value))
            {
                httpContext.Request.Body = DecryptStream(httpContext.Request.Body);
                var requestBody = await new StreamReader(httpContext.Request.Body).ReadToEndAsync();
                if (httpContext.Request.QueryString.HasValue)
                {
                    string decryptedString = DecryptString(httpContext.Request.QueryString.Value.Substring(1));
                    httpContext.Request.QueryString = new QueryString($"?{decryptedString}");
                }
            }
            await _next(httpContext);


            //// Read the request body
            //var requestBody = await new StreamReader(httpContext.Request.Body).ReadToEndAsync();

            //// Decrypt the request body using AES
            //var decryptedRequestBody = DecryptString(requestBody);

            //// Replace the request body with the decrypted version
            //httpContext.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(decryptedRequestBody));

            //// Call the next middleware in the pipeline
            //await _next(httpContext);
        }
        // This function is not needed but if we want anything to encrypt then we can use
        private CryptoStream EncryptStream(Stream responseStream)
        {
            Aes aes = GetEncryptionAlgorithm();
            ToBase64Transform base64Transform = new ToBase64Transform();
            CryptoStream base64EncodedStream = new CryptoStream(responseStream, base64Transform, CryptoStreamMode.Write);
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            CryptoStream cryptoStream = new CryptoStream(base64EncodedStream, encryptor, CryptoStreamMode.Write);
            return cryptoStream;
        }
        static byte[] Encrypt(string plainText)
        {
            byte[] encrypted;
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            return encrypted;
        }
        // This are main functions that we decrypt the payload and  parameter which we pass from the angular service.

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        private Stream DecryptStream(Stream cipherStream)
        {
            Aes aes = GetEncryptionAlgorithm();
            FromBase64Transform base64Transform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces);
            CryptoStream base64DecodedStream = new CryptoStream(cipherStream, base64Transform, CryptoStreamMode.Read);
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            CryptoStream decryptedStream = new CryptoStream(base64DecodedStream, decryptor, CryptoStreamMode.Read);
            return decryptedStream;
        }
        private string DecryptString(string cipherText)
        {
            Aes aes = GetEncryptionAlgorithm();
            byte[] buffer = Convert.FromBase64String(cipherText);
            MemoryStream memoryStream = new MemoryStream(buffer);
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            StreamReader streamReader = new StreamReader(cryptoStream);
            return streamReader.ReadToEnd();
        }
        // We have to use same KEY and IV as we use for encryption in angular side.
        // _appSettings.EncryptKey= 1203199320052021
        // _appSettings.EncryptIV = 1203199320052021
        private Aes GetEncryptionAlgorithm()
        {
            Aes aes = Aes.Create();
            var secret_key = Encoding.UTF8.GetBytes(_appSettings.EncryptKey);
            var initialization_vector = Encoding.UTF8.GetBytes(_appSettings.EncryptIV);
            aes.Key = secret_key;
            aes.IV = initialization_vector;
            return aes;
        }
        // This are excluded URL from encrypt- decrypt that already we added in angular side and as well as in ASP.NET CORE side.
        private List<string> GetExcludeURLList()
        {
            List<string> excludeURL = new();
            excludeURL.Add("/api/User/login");
            //excludeURL.Add("/api/Users/UploadProfilePicture");
            //excludeURL.Add("/api/Common/downloadattachedfile");
            return excludeURL;
        }
    }

}
