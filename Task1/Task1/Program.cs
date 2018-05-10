namespace Task1
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    public class Program
    {
        public static void Main(string[] args)
        {
            var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            var itercount = 100;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < itercount; i++)
            {
                GeneratePasswordHashUsingSalt("superPassword", salt);
            }

            sw.Stop();
            Console.WriteLine("Not optimized Time:" + sw.Elapsed.TotalMilliseconds + "ms");
            sw = Stopwatch.StartNew();
            for (int i = 0; i < itercount; i++)
            {
                OptimizedGeneratePasswordHashUsingSalt("superPassword", salt);
            }

            sw.Stop();
            Console.WriteLine("Optimized Time:" + sw.Elapsed.TotalMilliseconds + "ms");
            Console.ReadLine();
        }

        public static string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
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

        public static async Task<string> OptimizedGeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
        {
            var iterate = 10000;
            var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
            byte[] hash = await GetBytes(pbkdf2);
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, hashBytes, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            var passwordHash = Convert.ToBase64String(hashBytes);
            return passwordHash;
        }

        private static Task<byte[]> GetBytes(Rfc2898DeriveBytes rfc2898)
        {
            return Task.Run(() => rfc2898.GetBytes(20));
        }
    }
}
