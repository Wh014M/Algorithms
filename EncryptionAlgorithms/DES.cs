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
                using (SHA256CryptoServiceProvider _SHA256 = new SHA256CryptoServiceProvider())
                {
                    byte[] _Key = _SHA256.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _DES.KeySize = 0x100;
                        _DES.BlockSize = 0x80;
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
                using (SHA256CryptoServiceProvider _SHA256 = new SHA256CryptoServiceProvider())
                {
                    byte[] _Key = _SHA256.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _DES.KeySize = 0x100;
                        _DES.BlockSize = 0x80;
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