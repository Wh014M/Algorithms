using System.Security.Cryptography;
using System.Text;

namespace EncryptionAlgorithms
{
    public static class RC2
    {
        public static byte[] Encrypt(byte[] _Bytes, string _Password)
        {
            using (RC2CryptoServiceProvider _RC2 = new RC2CryptoServiceProvider())
            {
                using (MD5CryptoServiceProvider _MD5 = new MD5CryptoServiceProvider())
                {
                    byte[] _Key = _MD5.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _RC2.KeySize = 0x80;
                        _RC2.BlockSize = 0x40;
                        _RC2.Key = _Rfc2898DeriveBytes.GetBytes(_RC2.KeySize / 0x8);
                        _RC2.IV = _Rfc2898DeriveBytes.GetBytes(_RC2.BlockSize / 0x8);
                        _RC2.Mode = CipherMode.ECB;
                        _RC2.Padding = PaddingMode.PKCS7;

                        return _RC2.CreateEncryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }

        public static byte[] Decrypt(byte[] _Bytes, string _Password)
        {
            using (RC2CryptoServiceProvider _RC2 = new RC2CryptoServiceProvider())
            {
                using (MD5CryptoServiceProvider _MD5 = new MD5CryptoServiceProvider())
                {
                    byte[] _Key = _MD5.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _RC2.KeySize = 0x80;
                        _RC2.BlockSize = 0x40;
                        _RC2.Key = _Rfc2898DeriveBytes.GetBytes(_RC2.KeySize / 0x8);
                        _RC2.IV = _Rfc2898DeriveBytes.GetBytes(_RC2.BlockSize / 0x8);
                        _RC2.Mode = CipherMode.ECB;
                        _RC2.Padding = PaddingMode.PKCS7;

                        return _RC2.CreateDecryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }
    }
}