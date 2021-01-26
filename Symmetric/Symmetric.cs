using System.Security.Cryptography;
using System.Text;

namespace Symmetric
{
    public static class Symmetric
    {
        public static byte[] Encrypt(byte[] _Bytes, string _Password)
        {
            using (SymmetricAlgorithm _Symmetric = SymmetricAlgorithm.Create())
            {
                using (SHA256CryptoServiceProvider _SHA256 = new SHA256CryptoServiceProvider())
                {
                    byte[] _Key = _SHA256.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _Symmetric.KeySize = 0x100;
                        _Symmetric.BlockSize = 0x80;
                        _Symmetric.Key = _Rfc2898DeriveBytes.GetBytes(_Symmetric.KeySize / 0x8);
                        _Symmetric.IV = _Rfc2898DeriveBytes.GetBytes(_Symmetric.BlockSize / 0x8);
                        _Symmetric.Mode = CipherMode.ECB;
                        _Symmetric.Padding = PaddingMode.PKCS7;

                        return _Symmetric.CreateEncryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }

        public static byte[] Decrypt(byte[] _Bytes, string _Password)
        {
            using (SymmetricAlgorithm _Symmetric = SymmetricAlgorithm.Create())
            {
                using (SHA256CryptoServiceProvider _SHA256 = new SHA256CryptoServiceProvider())
                {
                    byte[] _Key = _SHA256.ComputeHash(Encoding.BigEndianUnicode.GetBytes(_Password));
                    byte[] _Salt = new byte[] { 0xAA, 0xFF, 0xBB, 0xCF, 0xCC, 0xDD, 0xDF, 0xAF };

                    using (Rfc2898DeriveBytes _Rfc2898DeriveBytes = new Rfc2898DeriveBytes(_Key, _Salt, 0x3E8))
                    {
                        _Symmetric.KeySize = 0x100;
                        _Symmetric.BlockSize = 0x80;
                        _Symmetric.Key = _Rfc2898DeriveBytes.GetBytes(_Symmetric.KeySize / 0x8);
                        _Symmetric.IV = _Rfc2898DeriveBytes.GetBytes(_Symmetric.BlockSize / 0x8);
                        _Symmetric.Mode = CipherMode.ECB;
                        _Symmetric.Padding = PaddingMode.PKCS7;

                        return _Symmetric.CreateDecryptor().TransformFinalBlock(_Bytes, 0x0, _Bytes.Length);
                    }
                }
            }
        }
    }
}