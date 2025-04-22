using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Lab3
{
    public static class RabinCryptosystem
    {
        private static Random random = new Random();

        public static BigInteger FastModPow(BigInteger a, BigInteger z, BigInteger n)
        {
            if (n == 0)
                throw new ArgumentException("Modulus cannot be zero.", nameof(n));
            if (z < 0)
                throw new ArgumentException("Exponent must be non-negative.", nameof(z));
            if (n == 1)
                return 0; // Согласно свойству: a^z mod 1 = 0 для любого a и z >= 0

            BigInteger a1 = a % n; // Убедимся, что a1 в диапазоне [0, n)
            BigInteger z1 = z;
            BigInteger x = 1;

            while (z1 != 0)
            {
                // Обрабатываем нечётные степени
                if (!z1.IsEven)
                {
                    x = (x * a1) % n;
                    z1 -= 1;
                }

                // Возводим в квадрат и уменьшаем степень вдвое
                a1 = (a1 * a1) % n;
                z1 /= 2;
            }

            return x;
        }


        // Проверка простоты тестом Миллера-Рабина
        public static bool IsPrime(BigInteger n, int k = 5)
        {
            if (n <= 1) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;

            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            for (int i = 0; i < k; i++)
            {
                BigInteger a = RandomInRange(2, n - 2);
                BigInteger x = FastModPow(a, d, n);
                if (x == 1 || x == n - 1) continue;

                for (int j = 0; j < s - 1; j++)
                {
                    x = FastModPow(x, 2, n);
                    if (x == n - 1) break;
                }

                if (x != n - 1) return false;
            }
            return true;
        }

        // Генерация случайного числа в диапазоне
        private static BigInteger RandomInRange(BigInteger min, BigInteger max)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do
            {
                random.NextBytes(bytes);
                result = new BigInteger(bytes);
            } while (result < min || result > max);
            return result;
        }

        // Расширенный алгоритм Евклида
        public static BigInteger[] ExtendedEuclid(BigInteger a, BigInteger b)
        {
            if (b == 0)
            {
                return new BigInteger[] { a, 1, 0 };
            }
            BigInteger[] vals = ExtendedEuclid(b, a % b);
            BigInteger d = vals[0];
            BigInteger x = vals[2];
            BigInteger y = vals[1] - (a / b) * vals[2];
            return new BigInteger[] { d, x, y };
        }

        // Шифрование байта 
        public static BigInteger Encrypt(byte m, BigInteger n, BigInteger b)
        {
            BigInteger mBig = new BigInteger(m);
            return (mBig * (mBig + b)) % n;
        }

        // Дешифрование
        public static byte Decrypt(BigInteger c, BigInteger p, BigInteger q, BigInteger b)
        {
            BigInteger n = p * q;
            BigInteger D = (b * b + 4 * c) % n;

            // Вычисление корней по модулям p и q
            BigInteger mp = FastModPow(D, (p + 1) / 4, p);
            BigInteger mq = FastModPow(D, (q + 1) / 4, q);

            // Китайская теорема об остатках 
            BigInteger[] vals = ExtendedEuclid(p, q);
            BigInteger yp = vals[1];
            BigInteger yq = vals[2];

            // Все 4 корня
            BigInteger[] roots =
            {
                (yp * p * mq + yq * q * mp) % n,
                n - (yp * p * mq + yq * q * mp) % n,
                (yp * p * mq - yq * q * mp) % n,
                n - (yp * p * mq - yq * q * mp) % n
            };

            // Проверка корней и выбор правильного
            foreach (BigInteger root in roots)
            {
                BigInteger m = (-b + root) * ModInverse(2, n) % n;
                m = (m + n) % n; // Корректировка отрицательных значений

                if (m >= 0 && m <= 255)
                    return (byte)m;
            }

            throw new InvalidOperationException("Decryption failed");
        }

        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger g, x, y;
            BigInteger[] gcd = ExtendedEuclid(a, m);
            g = gcd[0];
            x = gcd[1];
            y = gcd[2];

            if (g != 1) throw new ArgumentException("Обратный элемент не существует");
            return (x % m + m) % m;
        }

        public static (bool, string) AreKeyValuesCorrect(BigInteger p, BigInteger q, BigInteger b)
        {
            bool areCorrect = true;
            string message = "";
            if (!IsPrime(p))
            {
                message += $"Число {p} не является простым!\n";
                areCorrect = false;
            }
            if (!IsPrime(q))
            {
                message += $"Число {q} не является простым!\n";
                areCorrect = false;
            }
            if (p % 4 != 3 || q % 4 != 3)
            {
                message += "p и q должны ≡ 3 mod 4\n";
                areCorrect = false;
            }
            if (b >= p * q)
            {
                message += "Число b должно быть меньше p * q!\n";
                areCorrect = false;
            }
            return (areCorrect, message);
        }

        public static byte[] EncryptBytes(byte[] input, BigInteger n, BigInteger b)
        {

            List<byte> result = new List<byte>();
            int size = 0;
            BigInteger nTemp = n;
            while (nTemp > 0)
            {
                nTemp /= 256;
                size++;
            }
            foreach (byte m in input)
            {
                // Шифруем байт
                BigInteger encrypted = Encrypt(m, n, b);
                byte[] bytes = new byte[size];
                for (int i = 0; i < size; i++)
                {
                    bytes[i] = (byte)(encrypted & 0b1111_1111);
                    encrypted >>= 8;
                }
                // Разбиваем ushort на два байта (little-endian)
                result.AddRange(bytes);
            }

            return result.ToArray();
        }

        public static byte[] DecryptBytes(byte[] encryptedData, BigInteger p, BigInteger q, BigInteger b)
        {
            List<byte> result = new List<byte>();
            int size = 0;
            BigInteger nTemp = p * q;
            while (nTemp > 0)
            {
                nTemp /= 256;
                size++;
            }
            for (int i = 0; i < encryptedData.Length; i += size)
            {
                BigInteger encrypted = 0;
                int shift = 0;
                // Собираем два байта в ushort (little-endian)
                for (int j = 0; j < size; j++)
                {
                    encrypted += encryptedData[i + j] << shift;
                    shift += 8;
                }

                // Дешифруем
                byte decrypted = Decrypt(encrypted, p, q, b);
                result.Add(decrypted);
            }

            return result.ToArray();
        }

        public static byte[] ToByteArray(ushort[] data)
        {
            byte[] bytes = new byte[data.Length * 2];
            for (int i = 0; i < data.Length; i++)
            {
                BitConverter.GetBytes(data[i]).CopyTo(bytes, i * 2);
            }
            return bytes;
        }
    }
}