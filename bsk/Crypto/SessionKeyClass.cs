using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace bsk
{
    class SessionKeyClass
    {
        private String sessionKeyString;
        private byte[] sessionKeyBytes;
        private String plainKeyString;
        private byte[] plainKeyBytes;

        private String salt;
        public SessionKeyClass(string key)
        {
            this.plainKeyString = key.Trim();
            this.plainKeyBytes = Encoding.UTF8.GetBytes(this.plainKeyString);
            GenerateSalt();
        }
        public SessionKeyClass(byte[] key)
        {
            this.plainKeyBytes = key;
            this.plainKeyString = Encoding.UTF8.GetString(this.plainKeyBytes);
            GenerateSalt();
        }
        public void SessionKeyGenerate(Boolean withSalt = false)
        {
            GenerateSalt();
            this.sessionKeyString = RSAWorkerClass.GetHashSha256(this.plainKeyString+((withSalt)?this.salt:String.Empty));
            this.sessionKeyBytes = Encoding.UTF8.GetBytes(this.plainKeyString);
            this.salt = String.Empty;
        }
        private void GenerateSalt()
        {
            using (RandomNumberGenerator random = new RNGCryptoServiceProvider()) {
                var timeNow = DateTime.Now;
                String timeStampNow = timeNow.ToString("yyyyMMddHHmmssffff");
                byte[] randomBytes = new byte[32];
                random.GetNonZeroBytes(randomBytes);
                this.salt = String.Empty;
                this.salt += timeStampNow;
                this.salt += Encoding.UTF8.GetString(randomBytes);
            }
        }

        public byte[] getSessionKeyBytes()
        {
            return sessionKeyBytes;
        }
        public String getSessionKeyString()
        {
            return sessionKeyString;
        }
        public static byte[] GenerateKey(int keySize)
        {
            keySize = keySize / 8; // dł klucza w bajtach
            byte[] key = new byte[keySize];
            using (RandomNumberGenerator random = new RNGCryptoServiceProvider()){
                for (int i = 0; i < 100; i++)
                {
                    random.GetNonZeroBytes(key);
                }

            }
            return key;
        }
        public static byte[] GenerateIV(int blockSize)
        {
            blockSize = blockSize / 8; // dł bloku w bajtach
            byte[] iv = new byte[blockSize];
            using (RandomNumberGenerator random = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 100; i++)
                {
                    random.GetNonZeroBytes(iv);
                }

            }
            return iv;
        }

    }
}
