using Microsoft.AspNetCore.Identity;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace MembershipRebootToAspNetIdentity.PasswordHasher
{
    /// <summary>
    /// Example of temporary password hasher when transitionsing from BrockAllen.MembershipReboot to AspNet.Identity without forcing the users to change password.
    /// </summary>
    public class PasswordHasher : IPasswordHasher<TUser> where TUser : class
    {
        private IPasswordHasher<TUser> passwordHasher;

        public PasswordHasher(IPasswordHasher<TUser> passwordHasher)
        {
            this.passwordHasher = passwordHasher;
        }

        public string HashPassword(TUser user, string password)
        {
            return passwordHasher.HashPassword(user, password);
        }

        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            // Check if the start of the password hash is formated in MembershipReboot format.
            // Please update this as it will be different depending on your hash.
            if (hashedPassword.StartsWith("3E800.") == false)
            {
                // Got to the default AspNet.Identity password hasher.
                return passwordHasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
            }
            else
            {
                // Check hash against the MembershipReboot password hashing functionality.
                var result = StartVerifyingHashedPassword(hashedPassword, providedPassword);

                // Convert the return format to AspNet.Identity result.
                if (result)
                {
                    return PasswordVerificationResult.Success;
                }
                else
                {
                    return PasswordVerificationResult.Failed;
                }
            }
        }

        //***************************************************//
        // Below code is for backwards compatability only. 
        // When all uses have changed passwords this custom implementation is no longer needed.
        // Source is from https://github.com/brockallen/BrockAllen.MembershipReboot/blob/f36d65d89e60b5a8838e1873c06aca33278bb1e4/src/BrockAllen.MembershipReboot/Crypto/System.Web.Helpers.Crypto.cs
        // With some modifications.
        //***************************************************//

        private const int PBKDF2IterCount = 1000; // default for Rfc2898DeriveBytes
        private const int PBKDF2SubkeyLength = 256 / 8; // 256 bits
        private const int SaltSize = 128 / 8; // 128 bits
        public const char PasswordHashingIterationCountSeparator = '.';

        private bool StartVerifyingHashedPassword(string hashedPassword, string password)
        {
            if (hashedPassword.Contains(PasswordHashingIterationCountSeparator))
            {
                var parts = hashedPassword.Split(PasswordHashingIterationCountSeparator);
                if (parts.Length != 2) return false;

                int count = DecodeIterations(parts[0]);
                if (count <= 0) return false;

                hashedPassword = parts[1];

                return VerifyHashedPassword(hashedPassword, password, count);
            }
            else
            {
                return VerifyHashedPassword(hashedPassword, password);
            }
        }

        private int DecodeIterations(string prefix)
        {
            int val;
            if (Int32.TryParse(prefix, System.Globalization.NumberStyles.HexNumber, null, out val))
            {
                return val;
            }
            return -1;
        }

        // hashedPassword must be of the format of HashWithPassword (salt + Hash(salt+input)
        private bool VerifyHashedPassword(string hashedPassword, string password, int iterationCount = PBKDF2IterCount)
        {
            if (hashedPassword == null)
            {
                throw new ArgumentNullException("hashedPassword");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            byte[] hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            // Verify a version 0 (see comment above) password hash.

            if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
            {
                // Wrong length or version header.
                return false;
            }

            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);
            byte[] storedSubkey = new byte[PBKDF2SubkeyLength];
            Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);

            byte[] generatedSubkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterationCount))
            {
                generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return ByteArraysEqual(storedSubkey, generatedSubkey);
        }

        // Compares two byte arrays for equality. The method is specifically written so that the loop is not optimized.
        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            bool areSame = true;
            for (int i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }
    }
}
