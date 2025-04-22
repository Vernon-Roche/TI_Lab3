using Microsoft.Win32;
using System.IO;
using System.Numerics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Lab3;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    byte[] sourceBytes = [];
    byte[] resultBytes = [];
    public MainWindow()
    {
        InitializeComponent();
    }

    private void Button_Click(object sender, RoutedEventArgs e)
    {
        BigInteger p, q, b;
        string pString, qString, bString;
        bool pCorrect, qCorrect, bCorrect;
        pString = tbP.Text;
        qString = tbQ.Text;
        bString = tbB.Text;
        pCorrect = BigInteger.TryParse(pString, out p);
        qCorrect = BigInteger.TryParse(qString, out q);
        bCorrect = BigInteger.TryParse(bString, out b);
        if (!pCorrect || !qCorrect || !bCorrect)
        {
            MessageBox.Show("Значения p, q и b должны быть числами!", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        else
        {
            bool areKeyValuesCorrect;
            string errorMessage;
            (areKeyValuesCorrect, errorMessage) = RabinCryptosystem.AreKeyValuesCorrect(p, q, b);
            if (!areKeyValuesCorrect)
            {
                MessageBox.Show($"{errorMessage}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (sourceBytes.Length == 0)
            {
                MessageBox.Show("Попытка зашифровать пустую строку.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                if (rbEncrypt.IsChecked.Value)
                {
                    resultBytes = RabinCryptosystem.EncryptBytes(sourceBytes, p * q, b);
                    int size = 0;
                    BigInteger n = p * q;
                    while (n > 0)
                    {
                        n /= 256;
                        size++;
                    }
                    PrintAsNBytesValues(resultBytes, tbResultText, size);
                }
                else
                {
                    resultBytes = RabinCryptosystem.DecryptBytes(sourceBytes, p, q, b);
                    PrintAsOneByteValues(resultBytes, tbResultText);
                }
            }
        }
    }

    private void MenuItemOpen_Click(object sender, RoutedEventArgs e)
    {
        InitializeNewSession();
        OpenFileDialog openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            string filePath = openFileDialog.FileName;
            try
            {
                sourceBytes = File.ReadAllBytes(filePath);
                PrintAsOneByteValues(sourceBytes, tbSourceText);
            }
            catch
            {
                MessageBox.Show("Ошибка чтения файла.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void MenuItemOpenEncrypted_Click(object sender, RoutedEventArgs e)
    {
        InitializeNewSession();
        string pString, qString;
        BigInteger p, q;
        pString = tbP.Text;
        qString = tbQ.Text;
        if (BigInteger.TryParse(pString, out p) && BigInteger.TryParse(qString, out q) && RabinCryptosystem.IsPrime(p) && RabinCryptosystem.IsPrime(q))
        {
            BigInteger n = p * q;

            int size = 0;
            while (n > 0)
            {
                n /= 256;
                size++;
            }

            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                try
                {
                    sourceBytes = File.ReadAllBytes(filePath);
                    if (sourceBytes.Length % size == 0)
                    {
                        PrintAsNBytesValues(sourceBytes, tbSourceText, size);
                    }
                    else
                    {
                        sourceBytes = [];
                        MessageBox.Show("Данный файл невозможно расшифровать введенными ключами.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch
                {
                    MessageBox.Show("Ошибка чтения файла.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
        else
        {
            MessageBox.Show("Перед открытием файла задайте простые p и q.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void PrintAsNBytesValues(byte[] sourceBytes, TextBox destination, int n)
    {
        StringBuilder sourceString = new StringBuilder();
        for (int i = 0; i < sourceBytes.Length; i = i + n)
        {
            BigInteger number = 0;
            int shift = 0;
            for (int j = 0; j < n; j++)
            {
                number += sourceBytes[i + j] << shift;
                shift += 8;
            }
            sourceString.Append(number.ToString() + " ");
        }
        destination.Text = sourceString.ToString();
    }

    private void PrintAsOneByteValues(byte[] sourceBytes, TextBox destination)
    {
        StringBuilder sourceString = new StringBuilder();
        for (int i = 0; i < sourceBytes.Length; i++)
        {
            sourceString.Append(sourceBytes[i].ToString() + " ");
        }
        destination.Text = sourceString.ToString();
    }

    private void MenuItemSave_Click(object sender, RoutedEventArgs e)
    {
        SaveFileDialog saveFileDialog = new SaveFileDialog();
        if (saveFileDialog.ShowDialog() == true)
        {
            string filePath = saveFileDialog.FileName;
            SaveDataToFile(filePath, resultBytes);
        }
    }

    private void InitializeNewSession()
    {
        tbSourceText.Text = "";
        tbResultText.Text = "";
        resultBytes = [];
        sourceBytes = [];
    }

    private void SaveDataToFile(string filePath, byte[] bytes)
    {
        try
        {
            File.WriteAllBytes(filePath, bytes);
        }
        catch
        {
            MessageBox.Show("Ошибка записи в файл.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void tbP_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (rbDecrypt.IsChecked.Value)
        {
            sourceBytes = [];
            resultBytes = [];
        }
    }

    private void rbDecrypt_Checked(object sender, RoutedEventArgs e)
    {
        miOpenPlaintext.IsEnabled = true;
        miSaveCiphertext.IsEnabled = true;
        miOpenCiphertext.IsEnabled = false;
        miSavePlaintext.IsEnabled = false;
        InitializeNewSession();
    }

    private void rbEncrypt_Checked(object sender, RoutedEventArgs e)
    {
        miOpenPlaintext.IsEnabled = false;
        miSaveCiphertext.IsEnabled = false;
        miOpenCiphertext.IsEnabled = true;
        miSavePlaintext.IsEnabled = true;
        InitializeNewSession();
    }
}