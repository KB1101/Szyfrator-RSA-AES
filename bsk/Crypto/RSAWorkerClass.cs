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

    class RSAWorkerClass
    {
        private int rsaKeySize = 2048; // RSA Key Size 
        public RSAParameters publicKey { get; set; }
        public RSAParameters privateKey { get; set; }

        private RSACryptoServiceProvider csp;
        private UserInfo user = null;
        public byte[] passwordHash = null;
        public static String getHashSha256(String plainText)
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
        public RSAWorkerClass()
        {
            csp = new RSACryptoServiceProvider();
        }
        public RSAWorkerClass(int keySize)
        {
            this.rsaKeySize = keySize;
            csp = new RSACryptoServiceProvider(rsaKeySize);
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
            user = new UserInfo();
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
            csp = new RSACryptoServiceProvider(((RSAParameters)user.rsaKey).Modulus.Length*8);
            csp.ImportParameters((RSAParameters)this.user.rsaKey);
            publicKey = csp.ExportParameters(false);
            if (!csp.PublicOnly) privateKey = csp.ExportParameters(true);
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
                var sw = new System.IO.StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream
                xs.Serialize(sw, privateKey);
                //get the string from the stream
                this.user.rsaKeyString = sw.ToString();
              
                // AES for Private Key Encryption

                byte[] bytesSha256Password = Encoding.UTF8.GetBytes(getHashSha256(password));
                byte[] excryptedPrivateKey = AESWorkerClass.fastECBStringEncryptor(this.user.rsaKeyString, bytesSha256Password);
                this.user.rsaKeyString = Convert.ToBase64String(excryptedPrivateKey);

                this.user.rsaKey = null;
            } else
                this.user.rsaKey = csp.ExportParameters(privateKeySerialization);


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
                user = new UserInfo();
                user = (UserInfo)serializer.Deserialize(fileStream);
                this.privateKey = new RSAParameters();
                this.publicKey = new RSAParameters();


                if (!String.IsNullOrEmpty(user.rsaKeyString))
                {
                    // jesli po deserializacji istnieje pole rasKeyString to znaczy ze mamy doczynienia z kluczem prywatnym
                    byte[] bytesSha256Password = Encoding.UTF8.GetBytes(getHashSha256(password));
                    this.passwordHash = bytesSha256Password;
                    byte[] encryptedRsaKeyBytes = Convert.FromBase64String(this.user.rsaKeyString);
                    byte[] decryptedPrivateKey = AESWorkerClass.fastECBStringDecryptor(encryptedRsaKeyBytes, bytesSha256Password);
                    this.user.rsaKeyString = Encoding.UTF8.GetString(decryptedPrivateKey);

                    // deserialzacja XML na RSAParametrs
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    var sr = new StringReader(this.user.rsaKeyString);
                    try { this.privateKey = (RSAParameters)xs.Deserialize(sr); }
                    catch (Exception ex)
                    {
                        csp = new RSACryptoServiceProvider(2048);
                        this.privateKey = csp.ExportParameters(true);
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
            this.user.encryptedSessionKey = csp.Encrypt(key,true);
        }
        public byte[] RSADecryptSessionKey(byte[] encrypted)
        {
         
                byte[] decrypted = csp.Decrypt(encrypted, true);
                return decrypted;
   
        }

        public void RSAConfig()
        {

                publicKey = csp.ExportParameters(false);
                privateKey = csp.ExportParameters(true);

                String publicKeyString;
                {
                    //we need some buffer
                    var sw = new System.IO.StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, publicKey);
                    //get the string from the stream
                    publicKeyString = sw.ToString();
                }
                Console.Out.WriteLine(publicKeyString);

                String privateKeyString;
                {
                    //we need some buffer
                    var sw = new System.IO.StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, privateKey);
                    //get the string from the stream
                    privateKeyString = sw.ToString();
                }
                Console.Out.WriteLine(privateKeyString);

                String plainText = "Performs asymmetric encryption and decryption using the implementation of the RSA algorithm provided by the cryptographic service provider (CSP). This class cannot be inherited.";
                byte[] plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
                byte[] encryptedText = csp.Encrypt(plainTextBytes, true);
                String encryptedTextBase64String = Convert.ToBase64String(encryptedText);
                byte[] encryptedTextBase64 = Convert.FromBase64String(encryptedTextBase64String);
                byte[] decryptedText = csp.Decrypt(encryptedText, true);
                String decryptedPlainText = System.Text.Encoding.UTF8.GetString(decryptedText);

                String sha256 = getHashSha256("1234");


            ////Do you know that every time you use a code like this:
            ////using (var rsa = new RSACryptoServiceProvider(1024))
            ////            {
            ////                // Do something with the key...
            ////                // Encrypt, export, etc.
            ////            }
            ////.NET(actually Windows) stores your key in a PERSISTENT key container -forever ? And that container is randomly generated by .NET...

            ////The result is:

            ////Any random RSA / DSA key you have EVER generated for the purpose of protecting data, creating custom X.509 certificate, etc.has LEAKED in the Windows file system.For everyone who has access to your account to claim it.And you thought your data was safe...
            ////  Your disk is being slowly filled with data.Normally not a big concern but it depends on your application(e.g.it might generates hundreds of keys every minute).
            ////  So what do you do to avoid this rather UNEXPECTED behavior ?
            ////using (var rsa = new RSACryptoServiceProvider(1024))
            ////            {
            ////                try
            ////                {
            ////                    // Do something with the key...
            ////                    // Encrypt, export, etc.
            ////                }
            ////                finally
            ////                {
            ////                    rsa.PersistKeyInCsp = false;
            ////                }
            ////            }
        }
    }
}
