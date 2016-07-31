using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto.Encryption
{
    /// <summary>
    /// Symmetric algorithm uses the same key for encryption/decryption. Advantages of symmetric algorithm:
    ///     1. Secure
    ///     2. Fast
    ///  Algorithms:
    ///     DES (Data Encryption Standard)
    ///     Triple DES
    ///     AES (Advanced Encryption Standard) - USE ONLY THIS
    ///         - Also called "Rijndael cipher" named after the 2 belgium crypographers who designed the algorithm
    ///   Key Management:
    ///      One of the biggest problems is to securely store symmetric key
    ///   Key length - 128/192/256 bits
    ///   Longer keys are exponentially more difficult to crack than shorter ones
    ///   In practice, 256-bit keys are used
    ///   
    ///   .NET provided symmetric algorithms:
    ///         SymmetricAlgorithm  (Base class) 
    ///             DESCryptoServiceProvider          - DES Implementation
    ///             TripleDESCryptoServiceProvider    - Triple DES Implementation
    ///             AesCryptoServiceProvider          - AES Implementation
    /// </summary>
    public class SymmetricAlgorithmHelper
    {
        /// <summary>
        /// Encrypts the provided inout data using AES symmetric algorithm
        /// </summary>
        /// <param name="inputData">Input data to be encrypted</param>
        /// <param name="symmetricKey">Symmetric key to be used for encryption</param>
        /// <param name="initializationVector">Initialization Vector</param>
        /// <returns></returns>
        public static byte[] EncryptAES(byte[] inputData,byte[] symmetricKey, byte[] initializationVector)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                // Set properties
                SetCommonProperties(aes, symmetricKey, initializationVector);

                // Encrypt the data
                return HandleAesCommon(aes, inputData, aes.CreateEncryptor());
            }
        }

        public static byte[] DecryptAES(byte[] encryptedData,byte[] symmetricKey,byte[] initializationVector)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                // Set properties
                SetCommonProperties(aes, symmetricKey, initializationVector);

                return HandleAesCommon(aes, encryptedData, aes.CreateDecryptor());
            }
        }

        private static void SetCommonProperties(SymmetricAlgorithm symmetricAlgorithm,byte[] symmetricKey, byte[] initializationVector)
        {
            // Set properties
            symmetricAlgorithm.Mode = CipherMode.CBC;
            symmetricAlgorithm.Padding = PaddingMode.PKCS7;
            symmetricAlgorithm.Key = symmetricKey;
            symmetricAlgorithm.IV = initializationVector;
        }

        private static byte[] HandleAesCommon(AesCryptoServiceProvider aes,byte[] inputData,ICryptoTransform cryptoTransform)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                CryptoStream cryptoStream = new CryptoStream(stream, cryptoTransform, CryptoStreamMode.Write);
                cryptoStream.Write(inputData, 0, inputData.Length);
                cryptoStream.FlushFinalBlock();

                return stream.ToArray();
            }
        }
    }
}
