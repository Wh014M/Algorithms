using System.Security.Cryptography;
using System.Text;

namespace EncryptionAlgorithms
{
    public static class DES
    {
        public static byte[] Encrypt(byte[] _Bytes, string _Password)
        {
            using (DESCryptoServiceProvider _DES = new DESCryptoServiceProvider())
            {
                using (MD5CryptoServiceProvider _MD5 = new MD5CryptoServiceProvider())
                {
                    byte[] _Key = _MD5.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _DES.KeySize = 0x40;
                        _DES.BlockSize = 0x40;
                        _DES.Key = _Rfc2898DeriveBytes.GetBytes(_DES.KeySize / 0x8);
                        _DES.IV = _Rfc2898DeriveBytes.GetBytes(_DES.BlockSize / 0x8);
                        _DES.Mode = CipherMode.ECB;
                        _DES.Padding = PaddingMode.PKCS7;

                        return _DES.CreateEncryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }

        public static byte[] Decrypt(byte[] _Bytes, string _Password)
        {
            using (DESCryptoServiceProvider _DES = new DESCryptoServiceProvider())
            {
                using (MD5CryptoServiceProvider _MD5 = new MD5CryptoServiceProvider())
                {
                    byte[] _Key = _MD5.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _DES.KeySize = 0x40;
                        _DES.BlockSize = 0x40;
                        _DES.Key = _Rfc2898DeriveBytes.GetBytes(_DES.KeySize / 0x8);
                        _DES.IV = _Rfc2898DeriveBytes.GetBytes(_DES.BlockSize / 0x8);
                        _DES.Mode = CipherMode.ECB;
                        _DES.Padding = PaddingMode.PKCS7;

                        return _DES.CreateDecryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }
    }
}