using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Xml;
using System.Xml.Serialization;
using bsk.Crypto.ThirdPartyCrypto;

namespace bsk
{
    [XmlRootAttribute("User", IsNullable = false)]
    public class ShortUser
    {
        [XmlElement ("Email")]
        public String email { set; get; }
        [XmlElement("SessionKey")]
        public byte[] sessionKey { set; get; }
    }

    [XmlRootAttribute("EncryptedFileHeader", IsNullable = false)]
    public class XmlAesHeader
    {
        //Algorithm
        [XmlElement("Algorithm")]
        public String algorithm { set; get; }
        // KeySize
        [XmlElement("KeySize")]
        public int keySize { set; get; }
        // BlockSize
        [XmlElement("BlockSize")]
        public int blockSize { set; get; }
        [XmlElement("FeedbackBlockSize")]
        public int feedbackBlockSize { set; get; }
        // CipherMode
        [XmlElement("CipherMode")]
        public CipherMode cipherMode { set; get; }
        // length of file
        [XmlElement("length")]
        public long lng { set; get; }
        // IV
        [XmlElement("IV")]
        public byte[] iv { set; get; }
        //ApprovedUsers
        [XmlArray("ApprovedUsers"), XmlArrayItem(typeof(ShortUser),ElementName = "User")]
        public List <ShortUser> users { set; get; }
    }

    public class AESWorkerClass
    {
        private AESConfigClass aesConfig;
        private MainWindow main;
        private RijndaelManaged aes;
        private String inFile;
        private String outFile;


        private List<UserInfo> users;
        public /*private */ XmlAesHeader xmlAesHeader { get; set; }
        private MemoryStream xmlMemoryStream;

        public AESWorkerClass(ref AESConfigClass aesConf, ref MainWindow main)
        {
            this.aesConfig = aesConf;
            this.main = main;
            this.aes = new RijndaelManaged();
        }
        ~AESWorkerClass()
        {
            aes.Clear();
            aes.Dispose();
            aes = null;
        }
        public void SetInFilePath(String text)
        {
            this.inFile = text;
        }
        public void SetOutFilePath(String text)
        {
            this.outFile = text;
        }
        public void AESEncryptConfig()
        {
            aes.BlockSize = this.aesConfig.blockSize;
            aes.KeySize = this.aesConfig.keySize;
            {
                int mode = (int)this.aesConfig.CipherMode;
                aes.Mode = (CipherMode)mode;
            }
            aes.IV = this.aesConfig.IV;
            aes.Key = this.aesConfig.key;

            aes.Padding = PaddingMode.PKCS7; // sprawdzić!!!
            if (aes.Mode == CipherMode.OFB || aes.Mode == CipherMode.CFB)
            {
                if (aes.Mode == CipherMode.OFB) aes.Padding = PaddingMode.Zeros; // sprawdzić
                aes.FeedbackSize = this.aesConfig.feedbackBlockSize;
            }

        }

        public void SetUserList(List<UserInfo> users)
        {
            this.users = users;
            this.xmlAesHeader = new XmlAesHeader();
            this.xmlAesHeader.users = new List<ShortUser>();

            foreach (var user in this.users)
            {
                ShortUser sUser = new ShortUser();
                sUser.email = user.email;
                sUser.sessionKey = user.encryptedSessionKey;
                xmlAesHeader.users.Add(sUser);
            }
            xmlAesHeader.algorithm = "AES";
            xmlAesHeader.keySize = aesConfig.keySize;
            xmlAesHeader.blockSize = aesConfig.blockSize;
            int mode = (int)this.aesConfig.CipherMode;
            xmlAesHeader.cipherMode = (CipherMode)mode;
            xmlAesHeader.iv = aesConfig.IV;
            xmlAesHeader.feedbackBlockSize = aesConfig.feedbackBlockSize;
        }

        private void ToMemorySerializator()
        {
            this.xmlMemoryStream = new MemoryStream();
            XmlSerializer xs = new XmlSerializer(typeof(XmlAesHeader));
            xs.Serialize(xmlMemoryStream, xmlAesHeader);

            // byte[] ss = xmlMemoryStream.ToArray();
            //  String str = Encoding.UTF8.GetString(ss);
        }
        public void AESEncrypt()
        {
            //create output file stream
            using (FileStream fileOutStream = new FileStream(outFile, FileMode.Create))
                // create input file stream
                using (FileStream fileInStream = new FileStream(inFile, FileMode.Open)) { 

                    //wielkosc pliku do XML
                    this.xmlAesHeader.lng = fileInStream.Length;

                // serializacja nagłowka do XML
                this.ToMemorySerializator();
                byte[] xmlHeaderBytes = this.xmlMemoryStream.ToArray();



                main.Dispatcher.BeginInvoke((Action)delegate
                {
                    main.encrypionProgressBar.Maximum = this.xmlAesHeader.lng;
                    main.encrypionProgressBar.Value = 0;
                });

                byte[] intBytes = BitConverter.GetBytes(xmlHeaderBytes.Length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(intBytes);
                byte[] result = intBytes;

                fileOutStream.Write(result, 0, 4); //-- zapisz wielkosc XML'a

                //zapisz xmlA
                fileOutStream.Write(xmlHeaderBytes, 0, xmlHeaderBytes.Length);

                //cryptostream 
                if (aes.Mode != CipherMode.OFB)
                {
                    CryptoStream cryptoStream = new CryptoStream(fileOutStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
                    byte[] buffer = new byte[1048576];
                    int read;

                    try
                    {
                        while ((read = fileInStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            // Application.DoEvents(); // -> for responsive GUI, using Task will be better!
                            cryptoStream.Write(buffer, 0, read);
                            main.Dispatcher.Invoke((Action)delegate
                            {
                                main.encrypionProgressBar.Value += read;

                            });

                        }

                        //close up
                        fileInStream.Close();
                        fileInStream.Dispose();

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error: " + ex.Message);
                    }
                    finally
                    {
                        cryptoStream.Close();
                        cryptoStream.Dispose();
                        this.xmlMemoryStream.Close();
                        this.xmlMemoryStream.Dispose();
                    }
                    try
                    {
                        fileOutStream.Close();
                        fileOutStream.Dispose();
                        
                        cryptoStream = null;
                        this.xmlMemoryStream = null;
                    }
                    catch (Exception) { };
                }
                else
                {

                    aes.Mode = CipherMode.OFB;
                    StreamCipher streamCipher = new StreamCipher(aes);

                    CryptoStream cryptoStream = new CryptoStream(fileOutStream, streamCipher.CreateEncryptor(), CryptoStreamMode.Write);
                    byte[] buffer = new byte[aes.FeedbackSize/8];
                    int read;

                    try
                    {
                        while ((read = fileInStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            // Application.DoEvents(); // -> for responsive GUI, using Task will be better!
                            main.Dispatcher.Invoke((Action)delegate
                            {
                                main.encrypionProgressBar.Value += read;

                            });


                            cryptoStream.Write(buffer, 0, read);
                            cryptoStream.Flush();
                        }

                        //close up
                        fileInStream.Close();

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error: " + ex.Message);
                    }
                    finally
                    {

                        cryptoStream.Close();
                        cryptoStream.Clear();
                        cryptoStream.Dispose();

                        this.xmlMemoryStream.Close();
                        this.xmlMemoryStream.Dispose();

                    }
                }
            }
    }

        public void AESDecrypt(String userMail, ref RSAWorkerClass rsa)
        {
            // create input file stream
            using (FileStream fileInStream = new FileStream(inFile, FileMode.Open))
            {

                byte[] length = new byte[4];
                fileInStream.Read(length, 0, length.Length); // pobranie dlogosci xml'a
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(length);

                int intLenght = BitConverter.ToInt32(length, 0);
                byte[] xlmBytes = new byte[intLenght];
                fileInStream.Read(xlmBytes, 0, intLenght);
                this.xmlMemoryStream = new MemoryStream(xlmBytes);

                main.Dispatcher.BeginInvoke((Action)delegate
                {
                    main.decryptionProgressBar.Maximum = fileInStream.Length;
                    main.decryptionProgressBar.Value = 0;
                });


                XmlSerializer xs = new XmlSerializer(typeof(XmlAesHeader));
                this.xmlAesHeader = (XmlAesHeader)xs.Deserialize(this.xmlMemoryStream);
                this.xmlMemoryStream.Close();
                this.xmlMemoryStream.Dispose();

                this.aesConfig.keySize = xmlAesHeader.keySize;

                this.aesConfig.blockSize = xmlAesHeader.blockSize;
                Boolean paddingZeros = false;


                foreach (var pUser in xmlAesHeader.users)
                {
                    if (pUser.email.Equals(userMail))
                    {
                        try
                        {
                            this.aesConfig.key = rsa.RSADecryptSessionKey(pUser.sessionKey);
                        }
                        catch (Exception)
                        {
                            this.aes.KeySize = this.aesConfig.keySize;
                            // this.aes.GenerateKey();
                            // this.aesConfig.key = this.aes.Key;
                            this.aesConfig.key = rsa.RSAGetPassword(this.aesConfig.keySize);
                            paddingZeros = true;
                        }
                        break;
                    }
                }

                this.aesConfig.IV = xmlAesHeader.iv;
                this.aesConfig.CipherMode = (AESConfigClass.ModeEnum)(xmlAesHeader.cipherMode);
                this.aesConfig.feedbackBlockSize = xmlAesHeader.feedbackBlockSize;

                this.AESEncryptConfig();
                if (paddingZeros) this.aes.Padding = PaddingMode.Zeros;


                CryptoStream cryptoStream;
                StreamCipher streamCipher;
                if (aes.Mode != CipherMode.OFB)
                {
                    cryptoStream = new CryptoStream(fileInStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
                }
                else
                {
                    aes.Mode = CipherMode.OFB;
                    streamCipher = new StreamCipher(aes);
                    cryptoStream = new CryptoStream(fileInStream, streamCipher.CreateDecryptor(), CryptoStreamMode.Read);
                }

                using (FileStream fileOutStream = new FileStream(outFile, FileMode.Create))
                {


                    int read;
                    byte[] buffer;

                    if (xmlAesHeader.lng > 1048576) buffer = new byte[1048576]; // 1MB buffer
                    else if (xmlAesHeader.lng > 1024) buffer = new byte[1024]; // 1kB buffer
                    else buffer = new byte[1]; //8bit buffer

                    if (aes.Mode == CipherMode.OFB) buffer = new byte[aes.FeedbackSize / 8];

                    try
                    {
                        while ((read = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            fileOutStream.Write(buffer, 0, read);

                            main.Dispatcher.Invoke((Action)delegate
                            {
                                main.decryptionProgressBar.Value += read;
                            });

                            if (fileOutStream.Length == xmlAesHeader.lng) break;

                            if ((fileOutStream.Length + buffer.Length) > xmlAesHeader.lng && (aes.Mode != CipherMode.OFB))
                            {
                                if (fileOutStream.Length + 1024 > xmlAesHeader.lng) buffer = new byte[1];
                                else buffer = new byte[1024];
                            }
                        }
                    }
                    catch (System.Security.Cryptography.CryptographicException ex_CryptographicException)
                    {
                        System.Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
                    }
                    catch (Exception ex)
                    {
                        System.Console.WriteLine("Error: " + ex.Message);
                    }

                    try
                    {
                        cryptoStream.Close();
                        cryptoStream.Dispose();
                    }
                    catch (Exception ex)
                    {
                        System.Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
                    }
                    finally
                    {
                        cryptoStream = null;
                        //fileOutStream.Close();
                        //fileOutStream.Dispose();
                    }
                        
                }
            }
        }

        /* -------------------------- STATIC FUNCTIONS ------------- */

        public static String MD5StringHash(String path) {
            StringBuilder str = new StringBuilder(); //= Encoding.UTF8.GetString(md5sum);
            try
            {
                using (var md5 = System.Security.Cryptography.MD5.Create()) using (var stream = File.OpenRead(@path))
                {
                    byte[] md5sum = md5.ComputeHash(stream);
                    foreach (byte bt in md5sum) str.Append(bt.ToString("x2"));
                }
            } catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"MD5StringHash Exception:{ex.ToString()}");
            }
            return str.ToString();
        }

        public static byte[] fastECBStringEncryptor(String plainText, byte[] key)
        {
            byte[] keyTrimed = new byte[16];
            for (int i = 0; i < 16; i++) keyTrimed[i] = key[i];

            var aesAlg = new AesManaged
            {
                KeySize = 128,
                Key = keyTrimed,
                BlockSize = 128,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
            };

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            return encryptor.TransformFinalBlock(plainBytes,0,plainBytes.Length);
        }

        public static byte[] fastECBStringDecryptor(byte[] encrypted, byte[] key)
        {
            /* obcinanie klucza do tablicy 16 elementowej po 8 bitow =>128bit klucz AES */
            byte[] keyTrimed = new byte[16];
            for (int i = 0; i < 16; i++) keyTrimed[i] = key[i];

            var aesAlg = new AesManaged
            {
                KeySize = 128,
                Key = keyTrimed,
                BlockSize = 128,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
            };

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        }
    }
}
