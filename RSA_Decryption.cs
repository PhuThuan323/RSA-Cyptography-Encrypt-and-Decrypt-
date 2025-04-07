using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RSA_Cryptography
{
    public partial class RSA_Decryption : Form
    {
        public RSA_Decryption()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (PPrime.Text == "" || QPrime.Text == "" || E_value.Text == "")
            {
                MessageBox.Show("Invalid Input! Please Check Again!", "Warning", MessageBoxButtons.OK);
            }
            if(ciphertext.Text == "")
            {
                MessageBox.Show("Please Enter Your Cipher Text!", "Warning", MessageBoxButtons.OK);
            }
            if(comboBox2.Text == "")
            {
                MessageBox.Show("Please Choose Your Output Format!", "Warning", MessageBoxButtons.OK);
            }
            try
            {
                BigInteger p = BigInteger.Parse(PPrime.Text);
                BigInteger q = BigInteger.Parse(QPrime.Text);
                

                if (!IsProbablyPrime(p) || !IsProbablyPrime(q))
                {
                    MessageBox.Show("P and Q must be prime numbers!", "Warning", MessageBoxButtons.OK);
                    return;
                }
                BigInteger e2 = BigInteger.Parse(E_value.Text);
                BigInteger d = CalculateD(e2, p, q);
                D_value.Text = d.ToString();
                BigInteger n = p * q;
                string[] encryptedBlocks = ciphertext.Text.Trim().Split(' ');
                List<byte> resultBytes = new List<byte>();

                foreach (string block in encryptedBlocks)
                {
                    BigInteger cipherBlock;

                    switch (comboBox2.Text)
                    {
                        case "HexaDecimal":
                            cipherBlock = BigInteger.Parse("0" + block, System.Globalization.NumberStyles.HexNumber);
                            break;

                        case "Decimal":
                            cipherBlock = BigInteger.Parse(block);
                            break;

                        case "Base64":
                            byte[] base64Bytes = Convert.FromBase64String(block);
                            cipherBlock = new BigInteger(base64Bytes);
                            break;

                        case "Binary":
                            cipherBlock = ConvertBinaryToBigInteger(block);
                            break;

                        case "Text":
                            cipherBlock = new BigInteger(Encoding.UTF8.GetBytes(block));
                            break;

                        default:
                            MessageBox.Show("Unsupported format selected!", "Error", MessageBoxButtons.OK);
                            return;
                    }

                    BigInteger decryptedBlock = BigInteger.ModPow(cipherBlock, d, n);
                    byte[] decryptedBytes = decryptedBlock.ToByteArray();

                    resultBytes.AddRange(decryptedBytes);
                }

                string decryptedText = Encoding.UTF8.GetString(resultBytes.ToArray()).Trim('\0');
                PlainText.Text = decryptedText;
                MessageBox.Show("Decryption Successful", "Success", MessageBoxButtons.OK);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Decryption failed: " + ex.Message, "Error", MessageBoxButtons.OK);
            }
        }
        private BigInteger ConvertBinaryToBigInteger(string binary)
        {
            return BigInteger.Parse("0" + Convert.ToInt64(binary, 2).ToString());
        }
        #region check prime
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
        #endregion

        private void RSA_Decryption_Load(object sender, EventArgs e)
        {

        }

        private void D_value_TextChanged(object sender, EventArgs e)
        {

        }

        #region Tinh D tu E
        public static BigInteger CalculateD(BigInteger e, BigInteger p, BigInteger q)
        {
            BigInteger phi = (p - 1) * (q - 1);
            return ModInverse(e, phi);
        }
        public static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                q = a / m;
                t = m;
                m = a % m;
                a = t;

                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }

            if (x1 < 0)
                x1 += m0;

            return x1;
        }
        #endregion
    }
}
