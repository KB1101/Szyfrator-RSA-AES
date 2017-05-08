using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace bsk
{
    
    class AESConfigClass
    {
        public enum ModeEnum
        {       
            CBC = 1,
            ECB = 2,
            OFB = 3,
            CFB = 4,
            CTS = 5
        };
        public int keySize {get; set;}
        public int blockSize { get; set; }
        public int feedbackBlockSize { get; set; }
        public ModeEnum CipherMode { get; set; }
        public byte[] IV { get; set; }
        public byte[] key { get; set; }
        public AESConfigClass()
        {
            this.keySize = 128;
            this.blockSize = 128;
            this.CipherMode = ModeEnum.CBC;
           
        }
        public AESConfigClass(int keySize, int blockSize)
        {
            this.keySize = keySize;
            this.blockSize = blockSize;
        }
        public AESConfigClass(int keySize, int blockSize, byte[] IV)
        {
            this.keySize = keySize;
            this.blockSize = blockSize;
            this.IV = IV;
        }
        public AESConfigClass(int keySize, int blockSize, byte[] IV, int feedBackSize)
        {
            this.keySize = keySize;
            this.blockSize = blockSize;
            this.IV = IV;
            this.feedbackBlockSize = feedBackSize;
        }

        internal void setWorkingMode(string text)
        {
            switch (text)
            {
                case "ECB":
                    this.CipherMode = ModeEnum.ECB;
                    break;
                case "CBC":
                    this.CipherMode = ModeEnum.CBC;
                    break;
                case "OFB":
                    this.CipherMode = ModeEnum.OFB;
                    break;
                case "CFB":
                    this.CipherMode = ModeEnum.CFB;
                    break;
                default:
                    this.CipherMode = ModeEnum.CBC;
                    break;
            }
        }
    }
}
