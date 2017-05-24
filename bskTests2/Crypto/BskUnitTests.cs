using Microsoft.VisualStudio.TestTools.UnitTesting;
using bsk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace bsk.Tests
{
    [TestClass()]
    public class BskUnitTests
    {
        public byte[] key = { 12,65,128,145,145,154,0xf8,54,0xab,0x9e,0x1c,0x6b,113,221,127,66};
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

                for(int z = 0; z < plain.Length; z++)
                {
                    if (plain[z] != decipher[z]) Assert.Fail();
                }

            } 
        }

        [TestMethod]
        public void AESWorkerEncryptTest()
        {
            MainWindow main = new MainWindow();

            AESWorkerClass aesWorker = new AESWorkerClass(ref main.aesConfig,ref main);

            main.aesConfig.key = key;
            main.aesConfig.IV = SessionKeyClass.GenerateIV(128);
            main.aesConfig.CipherMode = AESConfigClass.ModeEnum.ECB;
            main.aesConfig.blockSize = 128;
            main.aesConfig.feedbackBlockSize = 0;

            aesWorker.SetInFilePath(@"C:\Users\Kornel\Source\Repos\Szyfrator-RSA-AES\bskTests2\Resources\plik.pdf");
            aesWorker.SetOutFilePath("encrypted");

            List<UserInfo> users = new List<UserInfo>();
            for(var i = 0; i < 10; i++)
            {
                var user = new UserInfo();
                user.email = $"{i}@{i}.com";
                user.encryptedSessionKey = main.aesConfig.key;
                user.name = $"{i} - {i}";
                users.Add(user);
            }
            try
            {
                aesWorker.AESEncryptConfig();
                aesWorker.SetUserList(users);

                aesWorker.AESEncrypt();
            } catch (Exception)
            {
                Assert.Fail();
            }

        }
        [TestMethod]
        public void AESWorkerDecryt()
        {
            if (!File.Exists("encrypted")) Assert.Fail("Plik: encrypted nie istnieje");
            RSAWorkerClass rsa = new RSAWorkerClass(2048);
            
            MainWindow main = new MainWindow();
            main.aesConfig.key = key;
            rsa.GetUser().email = "0@0.com";
            rsa.GetUser().encryptedSessionKey = key;

            AESWorkerClass aesWorker = new AESWorkerClass(ref main.aesConfig, ref main);
            aesWorker.SetOutFilePath("decrypted");
            aesWorker.SetInFilePath("encrypted");
            rsa.passwordHash = key;

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


                aesWorker.AESDecrypt("0@0.com",ref rsa);

            var S1 = AESWorkerClass.MD5StringHash(@"C:\Users\Kornel\Source\Repos\Szyfrator-RSA-AES\bskTests2\Resources\plik.pdf");
            var S2 = AESWorkerClass.MD5StringHash("decrypted");
            if (!S1.Equals(S2)) Assert.Fail();

        }
    }
}