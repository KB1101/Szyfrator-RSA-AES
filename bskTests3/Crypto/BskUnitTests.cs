using Microsoft.VisualStudio.TestTools.UnitTesting;
using bsk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

namespace bsk.Tests
{
    [TestClass()]
    public class BskUnitTests
    {
        public byte[] key =  {
            12, 65, 128, 145, 145, 154, 0xf8, 54, 0xab, 0x9e, 0x1c, 0x6b, 113, 221, 127, 66
        };


        [TestMethod]
        public void RSAWorkerClassTest()
        {
            var rand = RandomNumberGenerator.Create();
            RSAWorkerClass rsa = new RSAWorkerClass(2048);

            byte[] plain = new byte[8];
            byte[] cipher;
            byte[] decipher;

            for (int i = 0; i < 10; i++)
            {
                plain = new byte[32 + (i * 8)];
                rand.GetBytes(plain);
                rsa.RSAEncryptSessionKey(plain);
                cipher = rsa.GetUser().encryptedSessionKey;
                decipher = rsa.RSADecryptSessionKey(cipher);

                for (int z = 0; z < plain.Length; z++)
                {
                    if (plain[z] != decipher[z]) Assert.Fail();
                }

            }
        }

        
        public long AESWorkerEncryptTest(byte[] aes_key = null,
            byte[] aes_iv = null,
            int block_size = 128,
            int feedback = 0,
            AESConfigClass.ModeEnum mode = AESConfigClass.ModeEnum.ECB
            )
        {
            long time = -1;
            if (aes_key == null) aes_key = key;
            if (aes_iv == null) aes_iv = SessionKeyClass.GenerateIV(128);

            MainWindow main = new MainWindow();
            AESWorkerClass aesWorker = new AESWorkerClass(ref main.aesConfig, ref main);

            main.aesConfig.key = aes_key;
            main.aesConfig.IV = aes_iv;
            main.aesConfig.CipherMode = mode;
            main.aesConfig.blockSize = block_size;
            main.aesConfig.feedbackBlockSize = feedback;

            aesWorker.SetInFilePath(@"C:\Users\Kornel\Source\Repos\Szyfrator-RSA-AES\bskTests3\Resources\BSK_instr_proj1_2017.pdf");
            aesWorker.SetOutFilePath("encrypted");

            List<UserInfo> users = new List<UserInfo>();
            for (var i = 0; i < 10; i++)
            {
                var user = new UserInfo();
                user.email = $"{i}@{i}.com";
                user.encryptedSessionKey = main.aesConfig.key;
                user.name = $"{i} - {i}";
                users.Add(user);
            }
            try
            {
                main.aesConfig.keySize = main.aesConfig.key.Length * 8;
                aesWorker.AESEncryptConfig();
                aesWorker.SetUserList(users);

                Stopwatch stopwatch = Stopwatch.StartNew();
                aesWorker.AESEncrypt();
                stopwatch.Stop();
                time = stopwatch.ElapsedMilliseconds;

      
            }
            catch (Exception)
            {
                Assert.Fail();
            }
            return time;

        }
        
        public long AESWorkerDecrytTest(byte[] aes_key = null)
        {
            long time = -1;
            if (aes_key == null) aes_key = key;
            if (!File.Exists("encrypted")) Assert.Fail("Plik: encrypted nie istnieje");
            RSAWorkerClass rsa = new RSAWorkerClass(2048);

            MainWindow main = new MainWindow();
            main.aesConfig.key = aes_key;
            rsa.GetUser().email = "0@0.com";
            rsa.GetUser().encryptedSessionKey = aes_key;

            AESWorkerClass aesWorker = new AESWorkerClass(ref main.aesConfig, ref main);
            aesWorker.SetOutFilePath("decrypted");
            aesWorker.SetInFilePath("encrypted");
            rsa.passwordHash = aes_key;

            List<UserInfo> users = new List<UserInfo>();
            for (var i = 0; i < 10; i++)
            {
                var user = new UserInfo();
                user.email = $"{i}@{i}.com";
                user.encryptedSessionKey = main.aesConfig.key;
                user.name = $"{i} - {i}";
                users.Add(user);
            }


            aesWorker.SetUserList(users);

            try
            {
                Stopwatch stopwatch = Stopwatch.StartNew();
                aesWorker.AESDecrypt("0@0.com", ref rsa);
                stopwatch.Stop();
                time = stopwatch.ElapsedMilliseconds;
            }
            catch (Exception)
            {
                Assert.Fail();
            }

            var S1 = AESWorkerClass.MD5StringHash(@"C:\Users\Kornel\Source\Repos\Szyfrator-RSA-AES\bskTests3\Resources\BSK_instr_proj1_2017.pdf");
            var S2 = AESWorkerClass.MD5StringHash("decrypted");
            if (!S1.Equals(S2)) Assert.Fail();
            return time;
        }

        [TestMethod]
        public void AESWorkerEncryptDecrypt_Test()
        {
            // Test szyfrowania i odszyfrowania pliku .pdf
            byte[] testKey = null;
            byte[] testIV = null;
            long testEncryptTime = 0;
            long testDecryptTime = 0;
            int testBlock = 128;
            int testFeedback = 0;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            int[] keySize = { 128, 192, 256 };
            int[] blockSize = { 128, 192, 256 };
            int[] feedbackSize = { 8, 16, 24, 32, 48, 64, 96, 128 };


            // ------------------------- ecb -------------------------
            foreach (var kSize in keySize)
            {
                foreach (var bSize in blockSize)
                {
                        testKey = new byte[kSize / 8];
                        testBlock = bSize;
                        testFeedback = 0;
                        testIV = new byte[testBlock / 8];

                        rng.GetNonZeroBytes(testKey);
                        rng.GetNonZeroBytes(testIV);
                        testEncryptTime = AESWorkerEncryptTest(testKey, testIV, testBlock, testFeedback, AESConfigClass.ModeEnum.ECB);
                        testDecryptTime = AESWorkerDecrytTest(testKey);
                       // Trace.WriteLine($"AES-{kSize}-{bSize}-ECB\n\t Encryption time: {testEncryptTime}ms \n\t Decryption time: {testDecryptTime}ms");
                    Trace.WriteLine($"AES-{kSize}-{bSize}-ECB;{testEncryptTime};{testDecryptTime}");
                }
            }

            //------------------------------ cbc -------------------------
            foreach (var kSize in keySize)
            {
                foreach (var bSize in blockSize)
                {
                    testKey = new byte[kSize / 8];
                    testBlock = bSize;
                    testFeedback = 0;
                    testIV = new byte[testBlock / 8];

                    rng.GetNonZeroBytes(testKey);
                    rng.GetNonZeroBytes(testIV);
                    testEncryptTime = AESWorkerEncryptTest(testKey, testIV, testBlock, testFeedback, AESConfigClass.ModeEnum.CBC);
                    testDecryptTime = AESWorkerDecrytTest(testKey);
                    //Trace.WriteLine($"AES-{kSize}-{bSize}-CBC\n\t Encryption time: {testEncryptTime}ms \n\t Decryption time: {testDecryptTime}ms");
                    Trace.WriteLine($"AES-{kSize}-{bSize}-CBC;{testEncryptTime};{testDecryptTime}");
                }
            }

            // --------------------------- cfb --------------------------------
            foreach (var kSize in keySize)
            {
                foreach (var bSize in blockSize)
                {
                    foreach (var fbSize in feedbackSize)
                    {
                        if (bSize % fbSize != 0) continue;

                        testKey = new byte[kSize / 8];
                        testBlock = bSize;
                        testFeedback = fbSize;
                        testIV = new byte[testBlock / 8];

                        rng.GetNonZeroBytes(testKey);
                        rng.GetNonZeroBytes(testIV);
                        testEncryptTime = AESWorkerEncryptTest(testKey, testIV, testBlock, testFeedback, AESConfigClass.ModeEnum.CFB);
                        testDecryptTime = AESWorkerDecrytTest(testKey);
                        // Trace.WriteLine($"AES-{kSize}-{bSize}-CFB/{fbSize}\n\t Encryption time: {testEncryptTime}ms \n\t Decryption time: {testDecryptTime}ms");
                        Trace.WriteLine($"AES-{kSize}-{bSize}-CFB/{fbSize}; {testEncryptTime};{testDecryptTime}");
                    }
                }
            }

            // --------------------------- ofb --------------------------------
            foreach (var kSize in keySize)
            {
                foreach (var bSize in blockSize)
                {
                    foreach (var fbSize in feedbackSize)
                    {
                        if (bSize % fbSize != 0) continue;

                        testKey = new byte[kSize / 8];
                        testBlock = bSize;
                        testFeedback = fbSize;
                        testIV = new byte[testBlock / 8];

                        rng.GetNonZeroBytes(testKey);
                        rng.GetNonZeroBytes(testIV);
                        testEncryptTime = AESWorkerEncryptTest(testKey, testIV, testBlock, testFeedback, AESConfigClass.ModeEnum.OFB);
                        testDecryptTime = AESWorkerDecrytTest(testKey);
                       // Trace.WriteLine($"AES-{kSize}-{bSize}-OFB/{fbSize}\n\t Encryption time: {testEncryptTime}ms \n\t Decryption time: {testDecryptTime}ms");
                        Trace.WriteLine($"AES-{kSize}-{bSize}-OFB/{fbSize};{testEncryptTime};{testDecryptTime}");
                    }
                }
            }


        }// end of function


    }
}