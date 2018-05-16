namespace Test
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using Task1;

    [TestClass]
    public class UnitTest1
    {
        private byte[] _salt;

        [TestInitialize]
        public void Init()
        {
            _salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        }

        [TestMethod]
        public void ExecutionSpeed()
        {
            var itercount = 100;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < itercount; i++)
            {
                GeneratePasswordHashUsingSalt("superPassword", _salt);
            }

            sw.Stop();
            var notOptimizedTime = sw.Elapsed.TotalMilliseconds;
            Console.WriteLine("Not optimized Time:" + notOptimizedTime + "ms");
            sw = Stopwatch.StartNew();
            for (int i = 0; i < itercount; i++)
            {
                GeneratePasswordHashUsingSalt_optimized("superPassword", _salt);
            }

            sw.Stop();
            var optimizedTime = sw.Elapsed.TotalMilliseconds;
            Console.WriteLine("Optimized Time:" + optimizedTime + "ms");
            Assert.IsTrue(notOptimizedTime > optimizedTime);
        }

        [TestMethod]
        public void EqualityCheck()
        {
            Console.WriteLine("Generated hash");
            var notOptimizedHash = GeneratePasswordHashUsingSalt("superPassword", _salt);
            var optimizedHash = GeneratePasswordHashUsingSalt_optimized("superPassword", _salt);
            Console.WriteLine(notOptimizedHash);
            Console.WriteLine(optimizedHash);
            Assert.IsTrue(notOptimizedHash == optimizedHash);
        }

        private static string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
        {
            var iterate = 10000;
            var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
            byte[] hash = pbkdf2.GetBytes(20);
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            var passwordHash = Convert.ToBase64String(hashBytes);
            return passwordHash;
        }

        private static string GeneratePasswordHashUsingSalt_optimized(string passwordText, byte[] salt)
        {
            var iterate = 10000;
            var pbkdf2 = new Rfc2898DeriveBytes_optimized(passwordText, salt, iterate);
            byte[] hash = pbkdf2.GetBytes(20);
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            var passwordHash = Convert.ToBase64String(hashBytes);
            return passwordHash;
        }
    }
}
