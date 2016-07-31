using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    /// <summary>
    /// 
    /// </summary>
    public class CryptoHelper
    {
        #region Members
        private static int SALTLENGTH = 8;
        #endregion Members

        #region Public Methods

        #region Salt Methods

        public static byte[] GenerateSalt(int saltLength = 32)
        {
            using (RNGCryptoServiceProvider randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var salt = new byte[saltLength];
                randomNumberGenerator.GetBytes(salt);

                return salt;
            }
        }

        #endregion Salt Methods

        #region Hashing Functions
        // Hashing Algorithms:
        // MD5 - DO NOT USE. Not Secure
        // SHA-1 - DO NOT USE. Not Secure
        // SHA-2 (SHA-256, SHA-512) - USE
        // SHA-3 - Not available as part of .NET Framework

            /// <summary>
            /// Computes hash of the given input using SHA-256 hashing algorithm
            /// </summary>
            /// <param name="inputVal">Input value to be hashed</param>
            /// <returns>Hash</returns>
        public static byte[] ComputeHashSha256(byte[] inputVal)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(inputVal);
            }
        }
        #endregion Hashing Functions

        #region Password-Related Methods

        public static byte[] GeneratePasswordHash(byte[] userSalt, string password)
        {
            // 1. Convert password to bytes array
            byte[] passwordBytes = CryptoHelper.ToBytes(password);
            // 2. Combine the password and salt to
            byte[] saltedPassword = CryptoHelper.Combine(passwordBytes, userSalt);
            // 3. Compute hash of the combined value
            byte[] hashedPassword = CryptoHelper.ComputeHashSha256(saltedPassword);
            return hashedPassword;
        }

        public static byte[] GeneratePasswordHash(byte[] salt,string password,int noOfIterations)
        {
            // 1. Convert password to bytes array
            byte[] passwordBytes = CryptoHelper.ToBytes(password);

            using (Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(passwordBytes, salt, noOfIterations))
            {
                return rfc2898.GetBytes(32);
            }
        }
        #endregion Password-Related Methods

        #region Helper Functions

        public static string ToBase64String(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        public static byte[] ToBytes(string stringVal)
        {
            return Encoding.UTF8.GetBytes(stringVal);
        }

        public static string GetString(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        #endregion Helper Functions

        #endregion Public Methods

        #region Private Methods
        private static byte[] Combine(byte[] first,byte[] second)
        {
            var outputByteArray = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, outputByteArray, 0, first.Length);
            Buffer.BlockCopy(second, 0, outputByteArray, first.Length, second.Length);

            return outputByteArray;
        }
        #endregion Private Methods
    }
}
