using Crypto.Encryption;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    class Program
    {
        static void Main(string[] args)
        {
            //for (int i = 0; i < 10; i++)
            //{
            //    Console.WriteLine("Salt " + i + " : " + CryptoHelper.ToBase64String(CryptoHelper.GenerateSalt(32)));
            //}

            //const string Message = "P@ssw0rd1988";

            //// 1. Get the user salt
            //byte[] salt = CryptoHelper.GenerateSalt();


            //// 2. Generate password hash
            //byte[] hashedPassword = CryptoHelper.GeneratePasswordHash(salt, Message);
            //string passwordHashString = CryptoHelper.ToBase64String(hashedPassword);
            ////Console.WriteLine("Salt: " + CryptoHelper.ToBase64String(salt));
            ////Console.WriteLine("Password hash: " + passwordHashString);

            //// PBKDF2
            //Pbkdf(salt, Message, 100);
            //Pbkdf(salt, Message, 1000);
            //Pbkdf(salt, Message, 5000);
            //Pbkdf(salt, Message, 10000);
            //Pbkdf(salt, Message, 50000);
            //Pbkdf(salt, Message, 100000);
            //Pbkdf(salt, Message, 200000);
            //Pbkdf(salt, Message, 500000);

            #region Symmetric Algorithm
            string plainData = "Data to encrypt";
            byte[] symmetricKey = CryptoHelper.GenerateSalt(32); // Symmetric key of 256-bit length
            byte[] initilizationVector = CryptoHelper.GenerateSalt(16);
            byte[] encryptedData = SymmetricAlgorithmHelper.EncryptAES(CryptoHelper.ToBytes(plainData), symmetricKey, initilizationVector);
            Console.WriteLine("Encrypted Data: " + CryptoHelper.ToBase64String(encryptedData));

            byte[] decryptedData = SymmetricAlgorithmHelper.DecryptAES(encryptedData, symmetricKey, initilizationVector);
            Console.WriteLine("Decrypted Data: " + CryptoHelper.GetString(decryptedData));
            #endregion Symmetric Algorithm
        }

        private static void Pbkdf(byte[] salt,string password,int iterations)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();

            var pbkdf1 = CryptoHelper.ToBase64String(CryptoHelper.GeneratePasswordHash(salt, password, iterations));

            sw.Stop();
            
            Console.WriteLine(string.Format("Iterations: {0} Hash: {1} Time: {2}ms", iterations, pbkdf1, sw.ElapsedMilliseconds));
        }
    }
}
