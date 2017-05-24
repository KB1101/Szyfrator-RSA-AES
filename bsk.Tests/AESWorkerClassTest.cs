// <copyright file="AESWorkerClassTest.cs">Copyright ©  2017</copyright>
using System;
using System.Collections.Generic;
using Microsoft.Pex.Framework;
using Microsoft.Pex.Framework.Validation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using bsk;

namespace bsk.Tests
{
    /// <summary>This class contains parameterized unit tests for AESWorkerClass</summary>
    [PexClass(typeof(AESWorkerClass))]
    [PexAllowedExceptionFromTypeUnderTest(typeof(InvalidOperationException))]
    [PexAllowedExceptionFromTypeUnderTest(typeof(ArgumentException), AcceptExceptionSubtypes = true)]
    [TestClass]
    public partial class AESWorkerClassTest
    {
        /// <summary>Test stub for AESDecrypt(String, RSAWorkerClass&amp;)</summary>
        [PexMethod]
        internal void AESDecryptTest(
            [PexAssumeUnderTest]AESWorkerClass target,
            string userMail,
            ref RSAWorkerClass rsa
        )
        {
            target.AESDecrypt(userMail, ref rsa);
            // TODO: add assertions to method AESWorkerClassTest.AESDecryptTest(AESWorkerClass, String, RSAWorkerClass&)
        }

        /// <summary>Test stub for AESEncryptConfig()</summary>
        [PexMethod]
        internal void AESEncryptConfigTest([PexAssumeUnderTest]AESWorkerClass target)
        {
            target.AESEncryptConfig();
            // TODO: add assertions to method AESWorkerClassTest.AESEncryptConfigTest(AESWorkerClass)
        }

        /// <summary>Test stub for AESEncrypt()</summary>
        [PexMethod]
        internal void AESEncryptTest([PexAssumeUnderTest]AESWorkerClass target)
        {
            target.AESEncrypt();
            // TODO: add assertions to method AESWorkerClassTest.AESEncryptTest(AESWorkerClass)
        }

        /// <summary>Test stub for .ctor(AESConfigClass&amp;, MainWindow&amp;)</summary>
        [PexMethod]
        internal AESWorkerClass ConstructorTest(ref AESConfigClass aesConf, ref MainWindow main)
        {
            AESWorkerClass target = new AESWorkerClass(ref aesConf, ref main);
            return target;
            // TODO: add assertions to method AESWorkerClassTest.ConstructorTest(AESConfigClass&, MainWindow&)
        }

        /// <summary>Test stub for MD5StringHash(String)</summary>
        [PexMethod]
        internal string MD5StringHashTest(string path)
        {
            string result = AESWorkerClass.MD5StringHash(path);
            return result;
            // TODO: add assertions to method AESWorkerClassTest.MD5StringHashTest(String)
        }

        /// <summary>Test stub for SetInFilePath(String)</summary>
        [PexMethod]
        internal void SetInFilePathTest([PexAssumeUnderTest]AESWorkerClass target, string text)
        {
            target.SetInFilePath(text);
            // TODO: add assertions to method AESWorkerClassTest.SetInFilePathTest(AESWorkerClass, String)
        }

        /// <summary>Test stub for SetOutFilePath(String)</summary>
        [PexMethod]
        internal void SetOutFilePathTest([PexAssumeUnderTest]AESWorkerClass target, string text)
        {
            target.SetOutFilePath(text);
            // TODO: add assertions to method AESWorkerClassTest.SetOutFilePathTest(AESWorkerClass, String)
        }

        /// <summary>Test stub for SetUserList(List`1&lt;UserInfo&gt;)</summary>
        [PexMethod]
        internal void SetUserListTest(
            [PexAssumeUnderTest]AESWorkerClass target,
            List<UserInfo> users
        )
        {
            target.SetUserList(users);
            // TODO: add assertions to method AESWorkerClassTest.SetUserListTest(AESWorkerClass, List`1<UserInfo>)
        }

        /// <summary>Test stub for fastECBStringDecryptor(Byte[], Byte[])</summary>
        [PexMethod]
        internal byte[] fastECBStringDecryptorTest(byte[] encrypted, byte[] key)
        {
            byte[] result = AESWorkerClass.fastECBStringDecryptor(encrypted, key);
            return result;
            // TODO: add assertions to method AESWorkerClassTest.fastECBStringDecryptorTest(Byte[], Byte[])
        }

        /// <summary>Test stub for fastECBStringEncryptor(String, Byte[])</summary>
        [PexMethod]
        internal byte[] fastECBStringEncryptorTest(string plainText, byte[] key)
        {
            byte[] result = AESWorkerClass.fastECBStringEncryptor(plainText, key);
            return result;
            // TODO: add assertions to method AESWorkerClassTest.fastECBStringEncryptorTest(String, Byte[])
        }
    }
}
