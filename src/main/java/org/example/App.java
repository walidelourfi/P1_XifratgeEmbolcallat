package org.example;

import org.example.Crypto.AsymmetricCrypto;
import org.example.Crypto.SymmetricCrypto;
import org.example.Models.CryptoModel;
import org.example.Tools.FileTools;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Console application entry point providing a simple menu to encrypt files.
 * <p>
 * Options:
 * 1) Symmetric AES encryption derived from a user password.
 * 2) Symmetric AES encryption with the AES key wrapped (encrypted) using an RSA public key.
 * </p>
 * All user-facing prompts remain in Catalan as per project requirements.
 */
public class App 
{
    /**
     * Prints the main menu to stdout.
     */
    private static void ShowMenu(){
        System.out.flush();
        System.out.print("--- Encriptador ---\n" +
                "1. Encriptar de forma simetrica\n" +
                "2. Encriptar de forma simetrica embolcallada\n" +
                "3. Sortir\n");

        System.out.print("-> ");
    }

    /**
     * Handles the "symmetric only" encryption flow.
     *
     * @param scanner input scanner shared with main loop
     */
    private static void SymmetricOnlyOption(Scanner scanner){
        System.out.flush();

        System.out.println("--- Encriptar de forma simetrica ---");

        String password = null;

        try{
            var console = System.console();
            if (console != null) {
                // Demanem la contrasenya sense eco a la consola
                password = Arrays.toString(console.readPassword("Introdueix la contrasenya: "));
            }

            System.out.print("\nIntrodueix la ruta absoluta del fitxer a encriptar: ");
            String fileToEncript = scanner.nextLine();

            System.out.print("\nIntrodueix la ruta absoluta del fitxer on es guardara (sense .bin): ");
            String savedEncrypted = scanner.nextLine() + ".bin";

            // Llegeix el fitxer font i en retorna els bytes
            byte[] dataToEncrypt = FileTools.readFile(fileToEncript);

            // Encripta amb AES derivant la clau de la contrasenya
            SymmetricCrypto symmetricCrypto = new SymmetricCrypto(256);
            symmetricCrypto.Encrypt(password, dataToEncrypt);
            symmetricCrypto.SaveEncryptedData(savedEncrypted);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    /**
     * Handles the symmetric encryption where the AES key is wrapped with an RSA public key.
     *
     * @param scanner input scanner shared with main loop
     */
    private static void SymmetricWrappedOption(Scanner scanner){
        System.out.flush();

        System.out.println("--- Encriptar de forma simetrica embolcallada ---");

        String password = null;

        try {
            var console = System.console();
            if (console != null) {
                // Demanem la contrasenya sense eco a la consola
                password = Arrays.toString(console.readPassword("Introdueix la contrasenya: "));
            }

            System.out.print("\nIntrodueix la ruta absoluta del fitxer a encriptar: ");
            String fileToEncript = scanner.nextLine();

            System.out.print("\nIntrodueix la ruta absoluta del fitxer on es guardara (sense .bin): ");
            String savedEncrypted = scanner.nextLine() + ".bin";

            System.out.print("\nIntrodueix la ruta absoluta del fitxer on es guardara la clau simetrica(sense .bin): ");
            String savedEncryptedKey = scanner.nextLine() + ".bin";

            System.out.print("\nIntrodueix la ruta absoluta del fitxer on es guardara la clau privada (sense .bin): ");
            String savedPrivateKey = scanner.nextLine() + ".bin";

            // Generem claus RSA per embolcallar la clau simetrica
            SymmetricCrypto symmetricCrypto = new SymmetricCrypto(256);
            AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(4096);

            CryptoModel cm = asymmetricCrypto.Generatekeys();

            // Llegeix i xifra, i desa tant les dades xifrades com la clau embolcallada
            byte[] dataToEncrypt = FileTools.readFile(fileToEncript);
            // NOTA: cal haver encriptat prèviament o haver generat la clau simètrica dins SymmetricCrypto
            symmetricCrypto.EncryptWrappedWithAsymmetric(cm.getPublicKey(), dataToEncrypt);
            symmetricCrypto.SaveEncryptedDataAndKey(savedEncrypted, savedEncryptedKey,  savedPrivateKey);

        } catch (Exception e) {}
    }

    /**
     * Program entry point. Launches the interactive menu loop.
     */
    public static void main( String[] args )
    {
        Scanner sc = new Scanner(System.in);
        boolean running = true;

        do{
            ShowMenu();

            String userInput = sc.nextLine();

            switch (userInput) {
                case "1":
                    SymmetricOnlyOption(sc);
                    break;
                case "2":
                    SymmetricWrappedOption(sc);
                    break;
                case "3":
                    running = false;
                    break;
                default:
                    System.out.println("Introduiex una opcio de les mostrades.");
            }
        } while (running);
    }
}
