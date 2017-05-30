using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Microsoft.Win32;
using System.IO;

namespace bsk
{
    /// <summary>
    /// Interaction logic for Window1.xaml
    /// </summary>
    public partial class GenerateKeyPairWindow : Window
    {
        private MainWindow mainWindow;
        private int rsaKeySizeForm = 2048;
        private String emailText;
        private String nameText;
        private String passwordText;

        private String rsaPrivateKeyLocation;
        private String rsaPublicKeyLocation;
        private Random rnd;

        public GenerateKeyPairWindow(ref MainWindow mainWindow)
        {
            InitializeComponent();
            this.mainWindow = mainWindow;
            rsaKeySize2048.IsChecked = true;

            rsaPrivateKeyLocation = this.mainWindow.getPrivateKeysDirPath();
            rsaPublicKeyLocation = this.mainWindow.getPublicKeysDirPath();
           rnd = new Random();

        }

        private void rsaKeySize2048_Checked(object sender, RoutedEventArgs e)
        {
            this.rsaKeySizeForm = 2048;
        }

        private void rsaKeySize1024_Checked(object sender, RoutedEventArgs e)
        {
            this.rsaKeySizeForm = 1024;
        }

        private void textBoxHaslo_LostFocus(object sender, RoutedEventArgs e)
        {
            if(textBoxHaslo.Password != textBoxHaslo2.Password ||
                textBoxHaslo2.Password == String.Empty)
            {
                textBoxHaslo.BorderBrush = Brushes.Red;
            } else {
                textBoxHaslo.BorderBrush = Brushes.Green;
                textBoxHaslo2.BorderBrush = Brushes.Green;
            }
        }

        private void textBoxHaslo2_LostFocus(object sender, RoutedEventArgs e)
        {
            if (textBoxHaslo.Password != textBoxHaslo2.Password || 
                textBoxHaslo2.Password.Trim() == String.Empty)
            {
                textBoxHaslo2.BorderBrush = Brushes.Red;
            } else {
                textBoxHaslo.BorderBrush = Brushes.Green;
                textBoxHaslo2.BorderBrush = Brushes.Green;
                this.passwordText = textBoxHaslo2.Password;
            }
        }

        private void textBoxEmail_LostFocus(object sender, RoutedEventArgs e)
        {
            if (textBoxEmail.Text.Trim() != String.Empty)
            {
                textBoxEmail.BorderBrush = Brushes.Green;
                this.emailText = textBoxEmail.Text.Trim();
            }
            else
            {
                textBoxEmail.BorderBrush = Brushes.Red;
            }
        }

        private void textBoxNazwa_LostFocus(object sender, RoutedEventArgs e)
        {
            if (textBoxNazwa.Text.Trim() != String.Empty)
            {
                textBoxNazwa.BorderBrush = Brushes.Green;
                this.nameText = textBoxNazwa.Text.Trim();
            }
            else
            {
                textBoxNazwa.BorderBrush = Brushes.Red;
            }
        }

        private void exitButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void startButton_Click(object sender, RoutedEventArgs e)
        {
            if (String.IsNullOrEmpty(emailText))
            {
                MessageBox.Show(this, "RSA Keys Generator", "Pole email jest puste");
                return;
            }
            if (String.IsNullOrEmpty(nameText))
            {
                MessageBox.Show(this, "RSA Keys Generator", "Pole nazwy użytkownka jest puste");
                return;
            }
            if (String.IsNullOrEmpty(passwordText))
            {
                MessageBox.Show(this, "RSA Keys Generator", "Pole hasła jest puste");
                return;
            }

            String filename = $"{this.nameText}_{rnd.Next(100, 10000)}";

            // tutaj zacznij generowanie
            if ((File.GetAttributes(this.rsaPublicKeyLocation) & FileAttributes.Directory) == FileAttributes.Directory)
            {
                this.rsaPublicKeyLocation = this.rsaPublicKeyLocation + $@"\{filename}.key"; 
            }
            if ((File.GetAttributes(this.rsaPrivateKeyLocation) & FileAttributes.Directory) == FileAttributes.Directory)
            {
                this.rsaPrivateKeyLocation = this.rsaPrivateKeyLocation + $@"\{filename}.privatekey";
            }
            RSAWorkerClass rsaConfig = new RSAWorkerClass(this.rsaKeySizeForm);
            if (String.IsNullOrEmpty(this.rsaPrivateKeyLocation))
                this.rsaPrivateKeyLocation = this.rsaPublicKeyLocation + ".privatekey";

            rsaConfig.UserConfig(this.emailText, 
                                this.nameText,  
                                this.rsaPublicKeyLocation, 
                                this.rsaPrivateKeyLocation);
            rsaConfig.RSAKeyToXml();
            rsaConfig.RSAKeyToXml(true,this.passwordText);

            //rsaConfig.RSAXmlToKey(this.rsaPublicKeyLocation, this.passwordText);

            MessageBox.Show(this,"Wygenerowano!","Generator kluczy RSA",MessageBoxButton.OK);
            rsaConfig = null;
            checkBox_Unchecked(sender, e);
        }

        private void buttonPrivateKeyLocation_Click(object sender, RoutedEventArgs e)
        {
            //lokalizacja klucza prywatnego
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "RSA Keys Files (*.privatekey)|*.privatekey";
            saveFileDialog.DefaultExt = "privatekey";
            saveFileDialog.AddExtension = true;
            if (saveFileDialog.ShowDialog() == true)
                rsaPrivateKeyLocation = saveFileDialog.FileName;
        }

        private void buttonPublicKeyLocation_Click(object sender, RoutedEventArgs e)
        {
            //lokalizacja klucza  publicznego
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "RSA Keys Files (*.key)|*.key";
            saveFileDialog.DefaultExt = "key";
            saveFileDialog.AddExtension = true;
            if (saveFileDialog.ShowDialog() == true)
                rsaPublicKeyLocation = saveFileDialog.FileName;
        }

        private void checkBox_Checked(object sender, RoutedEventArgs e)
        {
            buttonPrivateKeyLocation.IsEnabled = true;
            buttonPublicKeyLocation.IsEnabled = true;
        }

        private void checkBox_Unchecked(object sender, RoutedEventArgs e)
        {
            buttonPrivateKeyLocation.IsEnabled = false;
            buttonPublicKeyLocation.IsEnabled = false;
            rsaPrivateKeyLocation = this.mainWindow.getPrivateKeysDirPath();
            rsaPublicKeyLocation = this.mainWindow.getPublicKeysDirPath();
        }
    }
}
