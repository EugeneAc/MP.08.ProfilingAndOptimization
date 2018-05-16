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
               GeneratePasswordHashUsingSalt_optimized("superPassword", salt);
            }

            sw.Stop();
            Console.WriteLine("Optimized Time:" + sw.Elapsed.TotalMilliseconds + "ms");
            Console.WriteLine("Equality check");
            var p1 = GeneratePasswordHashUsingSalt("superPassword", salt);
            var p3 = GeneratePasswordHashUsingSalt_optimized("superPassword", salt);
            Console.WriteLine(p1);
            Console.WriteLine(p3);
            
            Console.WriteLine("Equality is "+ p1==p3);
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

        public static string GeneratePasswordHashUsingSalt_optimized(string passwordText, byte[] salt)
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
