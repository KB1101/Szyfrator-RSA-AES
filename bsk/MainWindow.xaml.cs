using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.IO;
using Microsoft.Win32;
using System.Xml.Serialization;


namespace bsk
{

    public partial class MainWindow : Window
    {
        private AESConfigClass aesConfig;
        private AESWorkerClass aesWorker;

        private Boolean feedbackBlockState;
        private Boolean md5sum;

        private String inFilePath;
        private String outFilePath;

        private String inEncryptedPath;
        private String outDecryptedPath;

        private String publicKeysDirPath;
        private String privateKeysDirPath;
        private enum tabEnum { Szyfrowanie, Deszyfrowanie, Tozsamosci }
        private tabEnum activeTab = tabEnum.Szyfrowanie;

        private GenerateKeyPairWindow window1;

        private List<String> keyFiles;
        private List<UserInfo> users;
        private List<UserInfo> selectedUsers;

        private List<String> privateKeyFiles;
        private List<UserInfo> privateUsers;
        private UserInfo selectedPrivateUser = null;

        private RSAWorkerClass rsaWorker;

        public String getPublicKeysDirPath()
        {
            return this.publicKeysDirPath;
        }
        public String getPrivateKeysDirPath()
        {
            return this.privateKeysDirPath;
        }

        public MainWindow()
        {
            string[] args = Environment.GetCommandLineArgs(); //weź argumenty z lini poleceń
            Dictionary<String, String> argsContener = new Dictionary<string, string>();


            //pobieranie argumentow z konsoli
            for (int index = 1; index < args.Length; index += 2) // od 1 bo pierwszy element zawsze jest nazwą programu w WINDOWS
            {
                argsContener.Add(args[index].Trim(), args[index + 1].Trim());
            }

            InitializeComponent(); // włacz GUI
            feedbackBlockState = false; //zablokuj na start pole FeedbackBlock(Size)

            // odpal aesa
            aesConfig = new AESConfigClass();
            var me = this;
            aesWorker = new AESWorkerClass(ref aesConfig, ref me);

            this.users = new List<UserInfo>(); // uzytkownicy klucza publicznego    
            this.selectedUsers = new List<UserInfo>(); // uzytkownicy klucza prywatnego/publicznego kotrzy zostali "wybrani"
            this.privateUsers = new List<UserInfo>(); // uzytkownicy klucza prywatnego

            string value;
            string arg = "--public-keys-dir";
            if (argsContener.TryGetValue(arg, out value))
            {
                this.publicKeysDirPath = value;
            }
            else this.publicKeysDirPath = @"BSKKeys\public";

            arg = "--private-keys-dir";
            if (argsContener.TryGetValue(arg, out value))
            {
                this.privateKeysDirPath = value;
            }
            else this.privateKeysDirPath = @"BSKKeys\private";

            arg = "--md5sum";
            if (argsContener.TryGetValue(arg, out value))
            {
                if (value.Equals("on"))
                {
                    this.md5sum = true;
                }
            }

            ProgramDataBaseDir();
            ShowPublicKeysList();
        }
        
        private void ProgramDataBaseDir()
        {
            // tworzenie katalogów dla kluczy, istotne!
            String[] directiories;
            StringBuilder path;
            try
            {
                directiories = this.publicKeysDirPath.Split('\\');
                path = new StringBuilder();
                foreach (var dir in directiories)
                {
                    path.Append(dir);
                    if (!Directory.Exists(path.ToString()))
                    {
                        // nie istnieje katalog
                        Directory.CreateDirectory(path.ToString());
                    }
                    path.Append(@"\");
                }
            }
            catch (IOException ex)
            {
                Console.WriteLine(ex.ToString());
            }
            try
            {
                directiories = this.privateKeysDirPath.Split('\\');
                path = new StringBuilder();
                foreach (var dir in directiories)
                {
                    path.Append(dir);
                    if (!Directory.Exists(path.ToString()))
                    {
                        // nie istnieje katalog
                        Directory.CreateDirectory(path.ToString());
                    }
                    path.Append(@"\");
                }

            }
            catch (IOException ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        private void ShowPublicKeysList()
        {
            String[] files = Directory.GetFiles(this.@publicKeysDirPath);
            this.keyFiles = new List<string>();
            foreach (var file in files)
            {
                if (Path.GetExtension(file).Equals(".key") || Path.GetExtension(file).Equals(".privatekey"))
                {
                    this.keyFiles.Add(file);
                }
            }
           this.updatePublicUsersList();
        }
        private void showPrivateKeysList()
        {
            String[] files = Directory.GetFiles(this.@privateKeysDirPath);
            this.privateKeyFiles = new List<string>();
            foreach (var file in files)
            {
                if (System.IO.Path.GetExtension(file).Equals(".key") || System.IO.Path.GetExtension(file).Equals(".privatekey"))
                {
                    this.privateKeyFiles.Add(file);
                }
            }
            updatePrivateUserList();
        }

        private void textBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        /* ---------------------- KONFIGI AES ---------------------- */
        private void Button_Click_keySize(object sender, RoutedEventArgs e)
        {
            (sender as Button).ContextMenu.IsEnabled = true;
            (sender as Button).ContextMenu.PlacementTarget = (sender as Button);
            (sender as Button).ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            (sender as Button).ContextMenu.IsOpen = true;
        }
        private void menuAESKeySize(object sender, EventArgs e)
        {
            var clicked = (sender as MenuItem);
            var textFromMenu = clicked.Header;
            dlkluczaText.Text = textFromMenu as String;

            aesConfig.keySize = Int32.Parse(dlkluczaText.Text);
        }
        private void Button_Click_BlockSize(object sender, RoutedEventArgs e)
        {
            (sender as Button).ContextMenu.IsEnabled = true;
            (sender as Button).ContextMenu.PlacementTarget = (sender as Button);
            (sender as Button).ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            (sender as Button).ContextMenu.IsOpen = true;
        }

        private void menuBlockSize(object sender, RoutedEventArgs e)
        {
            var clicked = (sender as MenuItem);
            var textFromMenu = clicked.Header;
            dlBlokuText.Text = textFromMenu as String;

            aesConfig.blockSize = Int32.Parse(dlBlokuText.Text);
        }
        private void Button_Click_TrybPracy(object sender, RoutedEventArgs e)
        {
            (sender as Button).ContextMenu.IsEnabled = true;
            (sender as Button).ContextMenu.PlacementTarget = (sender as Button);
            (sender as Button).ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            (sender as Button).ContextMenu.IsOpen = true;
        }
        private void menuTrybPracy(object sender, RoutedEventArgs e)
        {
            var clicked = (sender as MenuItem);
            var textFromMenu = clicked.Header;
            trybPracyText.Text = textFromMenu as String;

            aesConfig.setWorkingMode(trybPracyText.Text); // konfig

            // jesli CFB lub OFB to pozwól na zmiane długosci podbloku
            if(aesConfig.CipherMode == AESConfigClass.ModeEnum.CFB || aesConfig.CipherMode == AESConfigClass.ModeEnum.OFB)
            {
                feedbackBlockState = true;
                aesConfig.feedbackBlockSize = 8;
                textBlock_podblock.Background = Brushes.White;
                feedbackButton.Background = Brushes.White;
            } else {
                feedbackBlockState = false;
                textBlock_podblock.Background = new SolidColorBrush(Color.FromArgb(0xFF, 0xA2, 0xA2, 0xA2));
                feedbackButton.Background = new SolidColorBrush(Color.FromArgb(0xFF, 0xA2, 0xA2, 0xA2));
            }
        }

        private void Button_Click_FeedbackBlockSize(object sender, RoutedEventArgs e)
        {
            if (feedbackBlockState) // tylko dla OFB i CFB
            {
                (sender as Button).ContextMenu.IsEnabled = true;
                (sender as Button).ContextMenu.PlacementTarget = (sender as Button);
                (sender as Button).ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
                (sender as Button).ContextMenu.IsOpen = true;
            }
        }

        private void menuFeedbackBlockSize(object sender, RoutedEventArgs e)
        {
            var clicked = (sender as MenuItem);
            var textFromMenu = clicked.Header;
            dlPodblokuText.Text = textFromMenu as String;

            aesConfig.feedbackBlockSize= Int32.Parse(dlPodblokuText.Text);
        }
        /* --------------------- KONFIGI AES KONIEC ----------------------------------- */

        /* ----------------------- KONFIGI PLIKOW ------------------------------------ */
        private void Button_chose_in_file(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                    textBoxInFile.Text = openFileDialog.FileName;
                this.inFilePath = (textBoxInFile.Text).ToString();
                aesWorker.SetInFilePath(this.inFilePath);
            }
            catch (Exception)
            {
                DisplayErrorInfo("InFile","Brak praw odczytu");
            }
        }
        private void Button_chose_out_file(object sender, RoutedEventArgs e)
        {
            try
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog();
                if (saveFileDialog.ShowDialog() == true)
                    textBoxOutFile.Text = saveFileDialog.FileName;
                this.outFilePath = (textBoxOutFile.Text).ToString();
                aesWorker.SetOutFilePath(this.outFilePath);
            }
            catch (Exception)
            {
                DisplayErrorInfo("outFile", "Brak praw zapisu");
            }
        }
        /* ------------------------- KONFIGI PLIKOW KONIEC --------------------*/
       
         // Tutaj dodaje/usowa do listy selectedUsers klucze publiczne ktore sa zaznaczone do szyfrowania
        private void odbiorcyMenuUser_Click(object sender, RoutedEventArgs e)
        {
            var clicked = (sender as MenuItem);

            // wyszukiwanie który to klikniety został
            int itemIndex = 0;
            foreach (MenuItem item in odbiorcyMenuStack.Children)
            {
                if ((item.Header as String).Equals(clicked.Header as String)) break;
                itemIndex++;
            }
           
            int userID = 0;
            /* jeśli już dodany to wywal z selectedUsers */
            if ((odbiorcyMenuStack.Children[itemIndex] as MenuItem).Background == Brushes.LimeGreen)
            {
                (odbiorcyMenuStack.Children[itemIndex] as MenuItem).Background = Brushes.WhiteSmoke;
                // wyszukiwanie gościa klikniętego
                foreach (UserInfo user in this.selectedUsers)
                {
                    if (user.email.Equals(clicked.Header as String)) break;
                    userID++;
                }
                selectedUsers.RemoveAt(userID); // usun z listy
            }
            else /* dodaj do selectedUsers */
            {
                (odbiorcyMenuStack.Children[itemIndex] as MenuItem).Background = Brushes.LimeGreen; //zmien kolor tła !WAŻNE!
                foreach (UserInfo user in this.users) if (user.email.Equals(clicked.Header as String))
                    {
                        this.selectedUsers.Add(user); // dodaj do listy
                        break;
                    }
            }
            odbiorcyMenu.UpdateLayout();
        }
        private void updatePublicUsersList()
        {
            this.odbiorcyMenuStack.Children.Clear();
           // this.odbiorcyMenu.Items.Clear(); // wyczyść listę w GUI by wgrać nową
            this.selectedUsers.Clear(); // wyczyść listę wybranych użytkowników (odbiorców)
            this.users.Clear(); // wyczyść liste uzytkowników

            foreach (var keyFile in keyFiles) using (StreamReader streamReader = new StreamReader(keyFile))
                {
                    XmlSerializer xmlSerializer = new XmlSerializer(typeof(UserInfo));
                    UserInfo userInfo = new UserInfo();
                    userInfo = (UserInfo)xmlSerializer.Deserialize(streamReader);
                    userInfo.pubKeyLoc = keyFile;

                    // dodawaj tylko publiczne (mona zmienic na tez ze prywatne łyka bo czemu nie , nimi tez mozna szyfrowac)
                    if (userInfo.keyType.Equals("Public Key"))
                    {
                        this.users.Add(userInfo); // dodaj do listy uzytkowników

                        MenuItem newItem = new MenuItem(); // nowe munuItem -> kolecja uzyszkodników
                        newItem.Header = userInfo.email;
                        newItem.HorizontalAlignment = HorizontalAlignment.Left;
                        newItem.VerticalAlignment = VerticalAlignment.Top;
                        newItem.Background = Brushes.WhiteSmoke;
                        Thickness tx = new Thickness(1.0);
                        newItem.BorderThickness = tx;
                        newItem.BorderBrush = Brushes.SkyBlue;
                        newItem.Width = 380.0;
                        newItem.Click += odbiorcyMenuUser_Click;

                        // this.odbiorcyMenu.Items.Add(newItem); // dodaj do wyswietlenia
                        this.odbiorcyMenuStack.Children.Add(newItem);
                    }
                }
                
            odbiorcyMenu.UpdateLayout(); // wyświetl zmiany
        }

        // zmiania lokalizacji klucza publicznego (prywatnego) bedzie to używane w szyfrowaniu
        private void changeKeysLocalizationButton_Click(object sender, RoutedEventArgs e)
        {
            string[] files;
            using (var folderBrowserDialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                System.Windows.Forms.DialogResult result = folderBrowserDialog.ShowDialog();

                if (result == System.Windows.Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(folderBrowserDialog.SelectedPath))
                {
                    files = Directory.GetFiles(folderBrowserDialog.SelectedPath); // zwraca scieżki do plików w danym folderze w formacie tablicy

                    System.Windows.Forms.MessageBox.Show("Files found: " + files.Length.ToString(), "Message"); // potem niepotrzebne

                    this.keyFiles = new List<string>();
                    foreach (var file in files)
                    {
                        // dodawaj tylko pliki .key i .privatekey
                        if (System.IO.Path.GetExtension(file).Equals(".key") || System.IO.Path.GetExtension(file).Equals(".privatekey")) this.keyFiles.Add(file);
                    }
                    this.updatePublicUsersList(); //odśwież listę uzytkowników
                }
            }
        }

        // generowanie pary kluczy RSA - otwiera nowe okienko
        private void generateKeyButton_Click(object sender, RoutedEventArgs e)
        {
            var me = this;
            this.window1 = new GenerateKeyPairWindow(ref me);
            window1.Show();
        }

        /* -------------------------------------------------- AKCJA MIEDZY ZAKLADKAMI ------------------------------------ */
        private void tabSzyfrowanie_GotFocus(object sender, RoutedEventArgs e)
        {
            activeTab = tabEnum.Szyfrowanie;
            /* zmiana parametrow */
            if (null != this.inFilePath) aesWorker.SetInFilePath(this.inFilePath);
            if (null != this.outFilePath) aesWorker.SetOutFilePath(this.outFilePath);
        }

        private void tabDeszyfrowanie_GotFocus(object sender, RoutedEventArgs e)
        {
            activeTab = tabEnum.Szyfrowanie;
            /* zmiana parametrow */
            if (null != this.inEncryptedPath) aesWorker.SetInFilePath(this.inEncryptedPath);
            if (null != this.outDecryptedPath) aesWorker.SetOutFilePath(this.outDecryptedPath);
        }
        private void tabTozsamosci_GotFocus(object sender, RoutedEventArgs e)
        {
            activeTab = tabEnum.Tozsamosci; 
        }
        /* ----------------------------------------- KONIEC: AKCJA MIEDZY ZAKLADKAMI -------------------------------------------------*/
        private void buttonExit_Click(object sender, RoutedEventArgs e)
        {
            if (window1 != null && window1.ShowActivated) window1.Close();
            this.Close();
        }

      

    // do deszyfrowania ....

    private void buttonInEncryptedFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                    textBoxEncrypted.Text = openFileDialog.FileName;
                this.inEncryptedPath = (textBoxEncrypted.Text).ToString();

                aesWorker.SetInFilePath(this.inEncryptedPath);
           
                 this.showPrivateKeysList();
            }
            catch (Exception)
            {
                DisplayErrorInfo("InEncryptedFile Dialog", "Brak praw odczytu");
            }
        }

        private void buttonOutFileDecrypted_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog();
                if (saveFileDialog.ShowDialog() == true)
                    textBoxDecrypted.Text = saveFileDialog.FileName;
                this.outDecryptedPath = (textBoxDecrypted.Text).ToString();
                aesWorker.SetOutFilePath(outDecryptedPath);
            }
            catch (Exception)
            {
                DisplayErrorInfo("OutFilePath Dialog", "Brak praw zapisu");
            }
        }

        private void privateUser_Click(object sender, RoutedEventArgs e)
        {
            this.selectedPrivateUser = null;
            var clicked = (sender as MenuItem);
            int index = 0;
            for (int itemIndex = 0; itemIndex < stackKeys.Children.Count; itemIndex++)
            {
                (stackKeys.Children[itemIndex] as MenuItem).Background = Brushes.WhiteSmoke;

                MenuItem item = (MenuItem)stackKeys.Children[itemIndex];
                if ((item.Header as String).Equals(clicked.Header as String))
                {
                    index = itemIndex;
                }
            }

           (stackKeys.Children[index] as MenuItem).Background = Brushes.LimeGreen;
            prywatniOdbiorcyMenu.UpdateLayout();
            stackKeys.UpdateLayout();
            // moze jakos to zmienic finalne 
            foreach (var privUser in privateUsers)
            {
                if(privUser.email.Equals((clicked.Header as String)))
                {
                    this.selectedPrivateUser = privUser;
                    break;
                }
            }
            
        }
        private void updatePrivateUserList()
        {
            selectedPrivateUser = null;
            this.stackKeys.Children.Clear();
            this.privateUsers.Clear(); // wyczyść liste uzytkowników

            XmlSerializer xSerializer = new XmlSerializer(typeof(XmlAesHeader));
            byte[] xlmBytes = null;
            using (FileStream fileStream = new FileStream(this.inEncryptedPath, FileMode.Open))
            {
                try
                {
                    byte[] length = new byte[4];
                    fileStream.Read(length, 0, length.Length);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(length);

                    int intLenght = BitConverter.ToInt32(length, 0);
                    xlmBytes = new byte[intLenght];
                    fileStream.Read(xlmBytes, 0, intLenght);
                }
                catch (Exception)
                {
                    DisplayErrorInfo("FielReader", "FileReader: Brak dostępu do pliku lub plik uszkodzony");
                    return;
                }
            }
            try
            {
                MemoryStream xmlMemoryStream = new MemoryStream(xlmBytes);

                XmlAesHeader xmlHeader = (XmlAesHeader)xSerializer.Deserialize(xmlMemoryStream); //deserializacja nagłowka pliku 
                List<ShortUser> fromXMLFileUsersList = xmlHeader.users;

                xmlMemoryStream.Close();
                xmlMemoryStream.Dispose();

                foreach (var keyFile in privateKeyFiles) // przeglądanie tablicy kluczy
                {
                    using (StreamReader streamReader = new StreamReader(keyFile))
                    {
                        XmlSerializer xmlSerializer = new XmlSerializer(typeof(UserInfo));
                        UserInfo userInfo = new UserInfo();
                        userInfo = (UserInfo)xmlSerializer.Deserialize(streamReader);
                        userInfo.privKeyLoc = keyFile;

                        foreach (ShortUser suser in fromXMLFileUsersList)
                        {
                            if (suser.email.Equals(userInfo.email) && userInfo.keyType.Equals("Private Key"))
                            {
                                this.privateUsers.Add(userInfo);

                                MenuItem newItem = new MenuItem();
                                newItem.Header = userInfo.email;
                                newItem.HorizontalAlignment = HorizontalAlignment.Left;
                                newItem.VerticalAlignment = VerticalAlignment.Top;
                                newItem.Background = Brushes.WhiteSmoke;
                                Thickness tx = new Thickness(1.0);
                                newItem.BorderThickness = tx;
                                newItem.BorderBrush = Brushes.SkyBlue;
                                newItem.Width = 300.0;
                                Thickness px = new Thickness(-29.0, 0.0, -28.0, 0.0);
                                newItem.Padding = px;
                                newItem.Click += privateUser_Click;

                                stackKeys.Children.Add(newItem);
                                break;
                            } // end if
                        } // end foreach > fromXMLFileUsersList
                    } // end streamReader
                } //end foreach > privateKeyFiles
                prywatniOdbiorcyMenu.UpdateLayout();
                stackKeys.UpdateLayout();
            } catch (Exception ex)
            {
                DisplayErrorInfo("File deserializer", $"Bład deserializacji\n{ex.ToString()}");
            }
        }


        private void buttonPrivateKeyLocalization_Click(object sender, RoutedEventArgs e)
        {
            string[] files;
            using (var folderBrowserDialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                System.Windows.Forms.DialogResult result = folderBrowserDialog.ShowDialog();

                if (result == System.Windows.Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(folderBrowserDialog.SelectedPath))
                {
                    files = Directory.GetFiles(folderBrowserDialog.SelectedPath);

                    System.Windows.Forms.MessageBox.Show("Files found: " + files.Length.ToString(), "Message");

                    this.privateKeyFiles = new List<string>();
                    foreach (var file in files)
                    {
                        if (System.IO.Path.GetExtension(file).Equals(".key") || System.IO.Path.GetExtension(file).Equals(".privatekey"))
                        {
                            this.privateKeyFiles.Add(file);
                        }
                    }
                    this.updatePrivateUserList();
                }
            }

        }
        private void DisplayErrorInfo(String from, String info)
        {
            MessageBox.Show(this, $"Bład: {info}", $"{from}", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            // stage1: inFilePath null or empty checking
            if (String.IsNullOrEmpty(this.inEncryptedPath))
            {
                DisplayErrorInfo("Decryptor", "Brak pliku wejściowego!");
                return;
            }
            // stage2: outFilePath null or empty checking
            if (String.IsNullOrEmpty(this.outDecryptedPath))
            {
                DisplayErrorInfo("Decryptor", "Brak pliku wyjściowego!");
                return;
            }
            // stage3: no one user selected
            if (selectedPrivateUser == null)
            {
                DisplayErrorInfo("Decryptor", "Brak wybranego użytkownika klucza prywatnego");
                return;
            }
            String passwordPlainText = this.passwordBox.Password as String;
            // stage4: no password
            if (String.IsNullOrEmpty(passwordPlainText))
            {
                DisplayErrorInfo("Decryptor", "Nie podano hasła klucza prywatnego");
                return;
            }
            aesWorker.SetInFilePath(this.inEncryptedPath);
            aesWorker.SetOutFilePath(this.outDecryptedPath);
            this.rsaWorker = new RSAWorkerClass();
            try
            {
                rsaWorker.RSAXmlToKey(this.selectedPrivateUser.privKeyLoc, passwordPlainText);
            } catch(Exception ex)
            {
                DisplayErrorInfo("Decryptor", $"Bład w czasie odczytu klucza prywatnego/n{ex.ToString()}");
                return;
            }

            var me = this;
            Task.Run(() =>
            {
                aesWorker.AESDecrypt(selectedPrivateUser.email, ref rsaWorker);
                this.Dispatcher.BeginInvoke((Action)delegate
                {
                    MessageBox.Show(me, $"Plik: {inEncryptedPath} został odszyfrowany jako: {outDecryptedPath}");
                    if (me.md5sum) MessageBox.Show($"Wartość sumy MD5 pliku: {outDecryptedPath} wynosi:\n {AESWorkerClass.MD5StringHash(me.outDecryptedPath)}");
                    me.decryptionProgressBar.Value = 0.0;
                });

            });
        }


        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            // preparing to encrypt

            // stage1: inFilePath null or empty checking
            if (String.IsNullOrEmpty(this.inFilePath))
            {
                DisplayErrorInfo("Encryptor", "Brak pliku wejściowego!");
                return;
            }
            // stage2: outFilePath null or empty checking
            if (String.IsNullOrEmpty(this.outFilePath))
            {
                DisplayErrorInfo("Encryptor", "Brak pliku wyjściowego!");
                return;
            }
            // if OFB or CFB cipher mode
            if (aesConfig.CipherMode == AESConfigClass.ModeEnum.OFB || aesConfig.CipherMode == AESConfigClass.ModeEnum.CFB)
            {
                // stage3: fedbackBloskSize equals blockSize 
                if (aesConfig.feedbackBlockSize == aesConfig.blockSize)
                {
                    DisplayErrorInfo("Encryptor", "Długość bloku jest taka sama jak długość podbloku");
                    return;
                }
                // stage4: blockSize cannot be divided by feedbackBlockSize
                if (aesConfig.blockSize % aesConfig.feedbackBlockSize != 0)
                {
                    DisplayErrorInfo("Encryptor", "Długość bloku nie jest podzielna przez długość podbloku");
                    return;
                }
            }
            // stage5: no one user selected
            if (selectedUsers.Count == 0)
            {
                DisplayErrorInfo("Encryptor", "Brak wybranych użytkowników!");
                return;
            }

            // wygeneruj klucz sesjii i wektor IV
            byte[] sessionAesKey = SessionKeyClass.GenerateKey(aesConfig.keySize);
            aesConfig.key = sessionAesKey;
            byte[] sessionAesIV = SessionKeyClass.GenerateIV(aesConfig.blockSize);
            aesConfig.IV = sessionAesIV;

            RSAWorkerClass rsaWorker;
            for (int index = 0; index < selectedUsers.Count; index++)
            {
                rsaWorker = new RSAWorkerClass();
                rsaWorker.UserConfig(selectedUsers[index]);
                rsaWorker.RSAEncryptSessionKey(aesConfig.key);
                selectedUsers[index] = rsaWorker.GetUser();
                rsaWorker = null;
            }
            try {
                aesWorker.AESEncryptConfig();
                aesWorker.SetInFilePath(this.inFilePath);
                aesWorker.SetOutFilePath(this.outFilePath);
                aesWorker.SetUserList(this.selectedUsers);
            }
            catch(Exception ex)
            {
                DisplayErrorInfo("Encryptor", $"Bład konfiguracji. \n{ex.ToString()}");
                return;
            }


            var me = this;
            Task.Run( () =>
            {
                aesWorker.AESEncrypt();
                this.Dispatcher.BeginInvoke((Action)delegate
                {
                    MessageBox.Show(me, $"Plik: {Path.GetFileName(inFilePath)} zaszyfrowany jako {Path.GetFileName(outFilePath)}!");
                    if (me.md5sum) MessageBox.Show($"Wartość sumy MD5 pliku: {inFilePath} wynosi:\n {AESWorkerClass.MD5StringHash(me.inFilePath)}");
                    me.encrypionProgressBar.Value = 0.0;
                });

            });

           

        }

        private void importKeyButton_Click(object sender, RoutedEventArgs e)
        {
            String rsaKeysFileLocalization;
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "RSA Keys File (*.key;*.privatekey)| *.key;*.privatekey";
            if (openFileDialog.ShowDialog() == true)
            {
                rsaKeysFileLocalization = openFileDialog.FileName;
         
                using (StreamReader streamReader = new StreamReader(@rsaKeysFileLocalization))
                {
                    XmlSerializer xmlSerializer = new XmlSerializer(typeof(UserInfo));
                    UserInfo userInfo = new UserInfo();
                    try
                    {
                        userInfo = (UserInfo)xmlSerializer.Deserialize(streamReader);
                    } catch (Exception ex)
                    {
                        MessageBox.Show(this,"Problem z odczytaniem klucza\nInfo: "+ex.Message,"Importowanie klucza",MessageBoxButton.OK,MessageBoxImage.Error);
                        return;
                    }

                    Boolean isPublicKey;
                    if (userInfo.keyType.Equals("Public Key"))
                    {
                        userInfo.pubKeyLoc = @rsaKeysFileLocalization;
                        isPublicKey = true;
                    } else {
                        userInfo.privKeyLoc = @rsaKeysFileLocalization;
                        isPublicKey = false;
                    }

                    String keyFileName = @"\imported_" + Path.GetFileName(@rsaKeysFileLocalization);
                    using(StreamWriter streamWriter = new StreamWriter((isPublicKey) ? this.publicKeysDirPath + keyFileName : this.privateKeysDirPath + keyFileName))
                    {
                        try
                        {
                            xmlSerializer.Serialize(streamWriter, userInfo);
                        } catch(Exception ex)
                        {
                            MessageBox.Show(this, "Problem z zapisaniem klucza\nInfo: " + ex.Message, "Importowanie klucza", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                    }
                    MessageBox.Show(this, "Klucz dodany do bazy pomyślnie");
                }
            }
        } //end > importKeyButton_Click

        private void ConfigReset(object sender, RoutedEventArgs e)
        {
            try
            {
                ShowPublicKeysList();
            } catch(Exception ex)
            {
                DisplayErrorInfo("PublicKeyList", "Nie można wyświetlić listy kluczy publicznych.");
            }
        }
    }
}
