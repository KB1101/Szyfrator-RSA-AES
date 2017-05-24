using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Xml.Serialization;
using System.IO;

namespace bsk
{
    [XmlRootAttribute("User", IsNullable = false)]
    public class UserInfo
    {
        [XmlElement ("Name")]
        public String name { get; set; }
        [XmlElement("Email")]
        public String email { get; set; }
        [XmlIgnore]
        public String pubKeyLoc { get; set; }
        [XmlIgnore]
        public String privKeyLoc { get; set; }
        [XmlIgnore]
        public byte[] encryptedSessionKey { get; set; }

        [XmlElement("KeyType")]
        public String keyType { get; set; }

        [XmlElement("RSAKey")]
        public RSAParameters? rsaKey { get; set; }
        public bool ShouldSerializersaKey()
        {
            return rsaKey.HasValue;
        }

        [XmlElement("RSAKeyBase64")]
        public string rsaKeyString { get; set; }
        public bool ShouldSerializersaKeyString()
        {
            return (rsaKeyString == String.Empty || rsaKeyString == null)? false : true;
        }
    }

    public class RSAWorkerClass
    {
        private int rsaKeySize = 2048; // RSA Key Size 
        public RSAParameters publicKey { get; set; }
        public RSAParameters privateKey { get; set; }

        private RSACryptoServiceProvider csp;
        private UserInfo user = null;
        public byte[] passwordHash = null;

        /* ------- STATIC FUNCTIONS ------ */
        public static String GetHashSha256(String plainText)
        {
            String hashString;
            using (SHA256Managed shaHash = new SHA256Managed())
            {
                byte[] plainTextxBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] hashBytes = shaHash.ComputeHash(plainTextxBytes);
                hashString = string.Empty;
                foreach (byte x in hashBytes)
                    hashString += String.Format("{0:x2}", x);
            }
            return hashString;
        }
        /* -------- NON STATIC FUNCTIONS ------ */
        public RSAWorkerClass()
        {
            csp = new RSACryptoServiceProvider();
        }
        public RSAWorkerClass(int keySize)
        {
            this.rsaKeySize = keySize;
            csp = new RSACryptoServiceProvider(rsaKeySize);
            this.user = new UserInfo();
        }
        ~RSAWorkerClass()
        {
            csp.PersistKeyInCsp = false;
            csp.Clear();
            csp.Dispose();
            csp = null;

            this.publicKey = new RSAParameters();
            this.privateKey = new RSAParameters();

            user.rsaKey = null;
            user.rsaKeyString = "";
            user = null;

            System.Diagnostics.Trace.WriteLine("RSAConfigClass's destructor is called.");
        }


        
        public void UserConfig(String email, String name, String pubLocation, String privLocation)
        {
            this.user = new UserInfo();
            this.user.email = email;
            this.user.name = name;
            this.user.pubKeyLoc = pubLocation;
            this.user.privKeyLoc = privLocation;

            this.publicKey = csp.ExportParameters(false);
            this.privateKey = csp.ExportParameters(true);
        }


        public void UserConfig(UserInfo user)
        {
            this.user = user;
            // zobacz czy dziala dl klucza
            try
            {
                csp = new RSACryptoServiceProvider(((RSAParameters)user.rsaKey).Modulus.Length * 8);
                csp.ImportParameters((RSAParameters)this.user.rsaKey);
                publicKey = csp.ExportParameters(false);
                if (!csp.PublicOnly) privateKey = csp.ExportParameters(true);
            } catch (Exception cex)
            {
                String keyLocalization = null;
                if (this.user.pubKeyLoc != null) keyLocalization = this.user.pubKeyLoc;
                else return;

                RSAXmlToKey(keyLocalization);
                csp = new RSACryptoServiceProvider(((RSAParameters)this.user.rsaKey).Modulus.Length * 8);
                csp.ImportParameters((RSAParameters)this.user.rsaKey);
                publicKey = csp.ExportParameters(false);

                if (!csp.PublicOnly) privateKey = csp.ExportParameters(true);
                

                System.Diagnostics.Trace.WriteLine($"UserConfig: {cex}");
            }
        }
        public UserInfo GetUser()
        {
            return this.user;
        }


        public void RSAKeyToXml(Boolean privateKeySerialization = false, String password = null)
        {
            this.user.keyType = (!privateKeySerialization) ? "Public Key" : "Private Key";

            if (privateKeySerialization && password != null)
            {
                //we need some buffer
                using (var sw = new System.IO.StringWriter())
                {
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, privateKey);
                    //get the string from the stream
                    this.user.rsaKeyString = sw.ToString();
                    // clear from memory
                    xs = null;
                }
                // AES for Private Key Encryption

                //get sha256 from password 
                byte[] bytesSha256Password = Encoding.UTF8.GetBytes(GetHashSha256(password));
                // encrypt private key (AES ECB 128)
                byte[] excryptedPrivateKey = AESWorkerClass.fastECBStringEncryptor(this.user.rsaKeyString, bytesSha256Password);
                // encrypted private key in bytes convert into string
                this.user.rsaKeyString = Convert.ToBase64String(excryptedPrivateKey);
                // clear not encrypted private key from memory
                this.user.rsaKey = null;
            }
            else
            {
                // if public key
                this.user.rsaKey = csp.ExportParameters(privateKeySerialization);
            }

            XmlSerializer serializer = new XmlSerializer(typeof(UserInfo));
            TextWriter writer = new StreamWriter((!privateKeySerialization) ? user.pubKeyLoc : user.privKeyLoc);
            try
            {
                serializer.Serialize(writer, user);
            } catch (Exception) { }
            finally
            {
                writer.Close();
                writer.Dispose();
                writer = null;
                serializer = null;
            }
            
        }

        public void RSAXmlToKey(String localization,String password = null)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(UserInfo));
            using (FileStream fileStream = new FileStream(localization, FileMode.Open))
            {
                this.user = new UserInfo();
                this.user = (UserInfo)serializer.Deserialize(fileStream);
                this.privateKey = new RSAParameters();
                this.publicKey = new RSAParameters();


                if (!String.IsNullOrEmpty(user.rsaKeyString))
                {
                    // jesli po deserializacji istnieje pole rasKeyString to znaczy ze mamy doczynienia z kluczem prywatnym
                    byte[] bytesSha256Password = Encoding.UTF8.GetBytes(GetHashSha256(password));
                    this.passwordHash = bytesSha256Password;
                    byte[] encryptedRsaKeyBytes = Convert.FromBase64String(this.user.rsaKeyString);
                    byte[] decryptedPrivateKey = AESWorkerClass.fastECBStringDecryptor(encryptedRsaKeyBytes, bytesSha256Password);
                    this.user.rsaKeyString = Encoding.UTF8.GetString(decryptedPrivateKey);

                    // deserialzacja XML na RSAParametrs
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    var sr = new StringReader(this.user.rsaKeyString);
                    try {
                        // try to deserialize 
                        this.privateKey = (RSAParameters)xs.Deserialize(sr);
                    }
                    catch (Exception)
                    {
                        // fake key
                        csp = new RSACryptoServiceProvider(2048);
                        this.privateKey = csp.ExportParameters(true);
                    }
                    finally
                    {
                        sr.Close();
                        sr.Dispose();
                        xs = null;
                    }
                    // zapisz klucz
                    user.rsaKey = (RSAParameters?)this.privateKey;
                }

                csp = new RSACryptoServiceProvider();
                csp.ImportParameters((RSAParameters)user.rsaKey);
                publicKey = csp.ExportParameters(false);
                if (!csp.PublicOnly) privateKey = csp.ExportParameters(true);
            }
            serializer = null;
        }
        public byte[] RSAGetPassword(int len)
        {
            byte[] keyTrimed = new byte[len/8];
            for (int i = 0; i < len / 8; i++) keyTrimed[i] = this.passwordHash[i];
            return keyTrimed;
        }
        public void RSAEncryptSessionKey(byte[] key)
        {
            try
            {
                this.user.encryptedSessionKey = csp.Encrypt(key, true);
            } catch (Exception) { }
        }
        public byte[] RSADecryptSessionKey(byte[] encrypted)
        {
            byte[] decrypted = null;
            try
            {
                decrypted = csp.Decrypt(encrypted, true);
            } catch (Exception ex) { throw ex; }
            return decrypted;
        }

    }
}
