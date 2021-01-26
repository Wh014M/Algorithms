using System.Security.Cryptography;
using System.Text;

namespace EncryptionAlgorithms
{
    public static class TripleDES
    {
        public static byte[] Encrypt(byte[] _Bytes, string _Password)
        {
            using (TripleDESCryptoServiceProvider _Triple_DES = new TripleDESCryptoServiceProvider())
            {
                using (SHA256CryptoServiceProvider _SHA256 = new SHA256CryptoServiceProvider())
                {
                    byte[] _Key = _SHA256.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _Triple_DES.KeySize = 0x100;
                        _Triple_DES.BlockSize = 0x80;
                        _Triple_DES.Key = _Rfc2898DeriveBytes.GetBytes(_Triple_DES.KeySize / 0x8);
                        _Triple_DES.IV = _Rfc2898DeriveBytes.GetBytes(_Triple_DES.BlockSize / 0x8);
                        _Triple_DES.Mode = CipherMode.ECB;
                        _Triple_DES.Padding = PaddingMode.PKCS7;

                        return _Triple_DES.CreateEncryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }

        public static byte[] Decrypt(byte[] _Bytes, string _Password)
        {
            using (TripleDESCryptoServiceProvider _Triple_DES = new TripleDESCryptoServiceProvider())
            {
                using (SHA256CryptoServiceProvider _SHA256 = new SHA256CryptoServiceProvider())
                {
                    byte[] _Key = _SHA256.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _Triple_DES.KeySize = 0x100;
                        _Triple_DES.BlockSize = 0x80;
                        _Triple_DES.Key = _Rfc2898DeriveBytes.GetBytes(_Triple_DES.KeySize / 0x8);
                        _Triple_DES.IV = _Rfc2898DeriveBytes.GetBytes(_Triple_DES.BlockSize / 0x8);
                        _Triple_DES.Mode = CipherMode.ECB;
                        _Triple_DES.Padding = PaddingMode.PKCS7;

                        return _Triple_DES.CreateDecryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }
    }
}