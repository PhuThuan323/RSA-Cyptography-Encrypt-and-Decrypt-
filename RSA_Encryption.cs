using System.DirectoryServices.ActiveDirectory;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RSA_Cryptography
{
    public partial class RSA_Encryption : Form
    {
        public RSA_Encryption()
        {
            InitializeComponent();

        }

        private void Generate_Click(object sender, EventArgs e)
        {
            if (checkBox1.Checked == true)
            {
                int bitLength = 128;
                BigInteger p = GenerateRandomPrime(bitLength);
                BigInteger q = GenerateRandomPrime(bitLength);
                int eBitLength = 16;
                BigInteger e_value = GenerateRandomPrime(eBitLength);
                E_value.Text = e_value.ToString();
                PPrime.Text = p.ToString();
                QPrime.Text = q.ToString();
                BigInteger n = p * q;
                N_Value.Text = n.ToString();

            }
            else
            {
                try
                {
                    BigInteger p = BigInteger.Parse(PPrime.Text);
                    BigInteger q = BigInteger.Parse(QPrime.Text);
                    BigInteger e1 = BigInteger.Parse(E_value.Text);

                    if (!IsProbablyPrime(p) || !IsProbablyPrime(q))
                    {
                        MessageBox.Show("p hoặc q không phải số nguyên tố!", "Warning", MessageBoxButtons.OK);
                        return;
                    }

                    BigInteger phi = (p - 1) * (q - 1);

                    if (BigInteger.GreatestCommonDivisor(e1, phi) != 1)
                    {
                        MessageBox.Show("Giá trị e không nguyên tố cùng nhau với φ(n) = (p - 1)(q - 1)!", "Warning", MessageBoxButtons.OK);
                        return;
                    }

                    BigInteger n = p * q;
                    N_Value.Text = n.ToString();
                    MessageBox.Show("Kiểm tra hợp lệ! Thông số được chấp nhận.", "Success", MessageBoxButtons.OK);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Lỗi nhập liệu: " + ex.Message, "Error", MessageBoxButtons.OK);
                }
            }
        }
        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked == true)
            {
                PPrime.Enabled = false;
                QPrime.Enabled = false;
                E_value.Enabled = false;
                Generate.Enabled = true;
            }
            else if (checkBox1.Checked == false)
            {
                PPrime.Enabled = true;
                QPrime.Enabled = true;
                E_value.Enabled = true;
                Generate.Enabled = false;
            }
        }


        #region Generate Random PrimeNumber
        public static bool IsProbablyPrime(BigInteger n, int k = 10)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;

            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[n.GetByteCount()];

                for (int i = 0; i < k; i++)
                {
                    BigInteger a;
                    do
                    {
                        rng.GetBytes(bytes);
                        a = new BigInteger(bytes);
                    } while (a < 2 || a >= n - 2);

                    BigInteger x = BigInteger.ModPow(a, d, n);
                    if (x == 1 || x == n - 1) continue;

                    bool continueOuter = false;
                    for (int r = 1; r < s; r++)
                    {
                        x = BigInteger.ModPow(x, 2, n);
                        if (x == 1) return false;
                        if (x == n - 1)
                        {
                            continueOuter = true;
                            break;
                        }
                    }

                    if (continueOuter) continue;

                    return false;
                }
            }

            return true;
        }

        public static BigInteger GenerateRandomPrime(int bitLength = 64)
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                while (true)
                {
                    byte[] bytes = new byte[(bitLength + 7) / 8];
                    rng.GetBytes(bytes);
                    bytes[bytes.Length - 1] |= 0x80; // Đảm bảo bit cao nhất là 1
                    BigInteger candidate = new BigInteger(bytes);
                    candidate = BigInteger.Abs(candidate);
                    candidate |= 1; // Đảm bảo số lẻ

                    if (IsProbablyPrime(candidate))
                        return candidate;
                }
            }
        }
        #endregion

        private void Encryption_Click(object sender, EventArgs e)
        {
            if(PPrime.Text == "" || QPrime.Text == "" || E_value.Text == "")
            {
                MessageBox.Show("Invalid Input, Please Check It Out Before Implementing Function", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            if(comboBox2.Text == "")
            {
                MessageBox.Show("Please Choose Your Input Format!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            if (PlainText.Text == "")
            {
                MessageBox.Show("Invalid Plaintext Input", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                try
                {
                    string selectedFormat = comboBox2.Text;

                    string plainText = PlainText.Text;
                    byte[] plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);

                    BigInteger n = BigInteger.Parse(N_Value.Text);
                    BigInteger E = BigInteger.Parse(E_value.Text);

                    StringBuilder cipherText = new StringBuilder();
                    int blockSize = 32;

                    for (int i = 0; i < plainTextBytes.Length; i += blockSize)
                    {
                        byte[] block = plainTextBytes.Skip(i).Take(blockSize).ToArray();
                        BigInteger message = new BigInteger(block);
                        BigInteger cipherBlock = BigInteger.ModPow(message, E, n);

                        string encryptedBlock = cipherBlock.ToString("X");
                        switch (selectedFormat)
                        {
                            case "Hexadecimal":
                                encryptedBlock = cipherBlock.ToString("X");
                                break;
                            case "Decimal":
                                encryptedBlock = cipherBlock.ToString();
                                break;
                            case "Base64":
                                byte[] cipherBytes = cipherBlock.ToByteArray();
                                encryptedBlock = Convert.ToBase64String(cipherBytes);
                                break;
                            case "Binary":
                                encryptedBlock = Convert.ToString((long)cipherBlock, 2);
                                break;
                            case "Text":
                                encryptedBlock = System.Text.Encoding.UTF8.GetString(cipherBlock.ToByteArray());
                                break;
                            default:
                                encryptedBlock = cipherBlock.ToString("X");
                                break;
                        }
                        cipherText.Append(encryptedBlock + " ");
                    }

                    ciphertext.Text = cipherText.ToString().Trim();
                    MessageBox.Show("Encryption Successful", "Success", MessageBoxButtons.OK);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Encryption failed: " + ex.Message, "Error", MessageBoxButtons.OK);
                }
            }
        }
        #region Ma hoa RSA va cac ham chuyen doi van ban
        // Hàm chuyển BigInteger thành hệ cơ số 64
        public static string ToBase64(BigInteger number)
        {
            string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            string result = "";

            while (number > 0)
            {
                result = alphabet[(int)(number % 64)] + result;
                number /= 64;
            }

            return result;
        }

        // Hàm chuyển chuỗi thành mảng số nguyên (tương tự như hàm ConvertStringToInt trong Python)
        public static List<BigInteger> ConvertStringToInt(string input, int byteLength)
        {
            List<BigInteger> result = new List<BigInteger>();
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            for (int i = 0; i < bytes.Length; i += byteLength)
            {
                byte[] chunk = new byte[Math.Min(byteLength, bytes.Length - i)];
                Array.Copy(bytes, i, chunk, 0, chunk.Length);
                result.Add(new BigInteger(chunk));
            }

            return result;
        }

        // Hàm mã hóa RSA chính
        public static string Encode(BigInteger n, BigInteger e, string P, string file)
        {
            string C = "";
            List<BigInteger> R = ConvertStringToInt(P, 4);
            List<BigInteger> A = CreateBigInt(R, n.ToString().Length);
            foreach (BigInteger i in A)
            {
                BigInteger M = BigInteger.ModPow(i, e, n);
                string MBase64 = ToBase64(M);
                C += MBase64 + " ";
            }
            return C;
        }

        // Hàm tạo BigInt có kích thước phù hợp với n
        public static List<BigInteger> CreateBigInt(List<BigInteger> inputList, int length)
        {
            List<BigInteger> result = new List<BigInteger>();
            foreach (BigInteger num in inputList)
            {
                result.Add(BigInteger.Abs(num));
            }
            return result;
        }
        #endregion

        private void button1_Click(object sender, EventArgs e)
        {
            this.Visible = false;
            RSA_Decryption ch = new RSA_Decryption();
            ch.ShowDialog();
            this.Visible = true;
        }
    }
}
