using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using WinRT.Interop;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace BitZ_Password_Generator
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            this.InitializeComponent();
        }

        private async void GenerateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Reset error message
                ErrorTextBlock.Visibility = Visibility.Collapsed;
                ErrorTextBlock.Text = string.Empty;

                bool includeUppercase = UppercaseCheckbox.IsChecked ?? false;
                bool includeLowercase = LowercaseCheckbox.IsChecked ?? true;
                bool includeNumbers = NumbersCheckbox.IsChecked ?? false;
                bool includeSpecialChars = SpecialCharsCheckbox.IsChecked ?? false;
                int passwordLength = (int)LengthSlider.Value;

                string password = await Task.Run(() => GeneratePassword(passwordLength, includeUppercase, includeLowercase, includeNumbers, includeSpecialChars));
                GeneratedPasswordTextBox.Text = password;
            }
            catch (InvalidOperationException ex)
            {
                // Display error message to the user
                ErrorTextBlock.Text = ex.Message;
                ErrorTextBlock.Visibility = Visibility.Visible;
            }
        }

        private string GeneratePassword(int length, bool includeUppercase, bool includeLowercase, bool includeNumbers, bool includeSpecialChars)
        {
            const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
            const string NumberChars = "0123456789";
            const string SpecialChars = "!@#$%^&*()_-+=<>?";

            StringBuilder charSet = new StringBuilder();

            if (includeUppercase) charSet.Append(UppercaseChars);
            if (includeLowercase) charSet.Append(LowercaseChars);
            if (includeNumbers) charSet.Append(NumberChars);
            if (includeSpecialChars) charSet.Append(SpecialChars);

            if (charSet.Length == 0)
                throw new InvalidOperationException("At least one character set must be selected.");

            char[] password = new char[length];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] data = new byte[length];
                rng.GetBytes(data);
                for (int i = 0; i < password.Length; i++)
                {
                    password[i] = charSet[data[i] % charSet.Length];
                }
            }
            return new string(password);
        }

        private async void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string password = GeneratedPasswordTextBox.Text;
            if (string.IsNullOrEmpty(password))
            {
                EncryptedPasswordTextBox.Text = "Generate a password first.";
                return;
            }

            string encryptedPassword = await Task.Run(() => EncryptPassword(password, "your-encryption-key"));
            EncryptedPasswordTextBox.Text = encryptedPassword;
        }

        private string EncryptPassword(string password, string key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(32));
                aesAlg.Key = keyBytes;
                aesAlg.GenerateIV();

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                byte[] encrypted;

                using (System.IO.MemoryStream msEncrypt = new System.IO.MemoryStream())
                {
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (System.IO.StreamWriter swEncrypt = new System.IO.StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(password);
                    }
                    encrypted = msEncrypt.ToArray();
                }
                return Convert.ToBase64String(encrypted);
            }
        }
    }
}
