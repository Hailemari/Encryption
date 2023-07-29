/*
 * A client side program to encrypt and decrypt a message using a symmetric session key generated 
 * and shared by DH and using AES algorithm
 * 
 * GROUP MEMBERS                                 ID
 * 1. Hailemariam Kefale                      UGR/0652/12
 * 2. Zienamarkos Molla                       UGR/4176/12
 * 3. Genzeb Alemu                           UGR/9822/12
 */
import java.security.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Arrays;
import java.math.*;
import java.net.*;
import java.io.*;

public class DHClient {

    public static int keyLength = 1024;

    static BufferedReader userResponse = new BufferedReader(new InputStreamReader(System.in));
    static String IV = "CFQSPABSYUZXLGME";

    // a function that encrypts a plaintext using a session key
    public static byte[] encrypt(String plainText, BigInteger sessionKey) throws Exception {

        byte[] secretKey = sessionKey.toByteArray();
        secretKey = Arrays.copyOf(secretKey, 16);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec key = new SecretKeySpec(secretKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));

        /* ensure that the plaintext message is a multiple of 16 bytes as the AES algorithm works with blocks of 16 bytes
        * If the plaintext message is not a multiple of 16 bytes, the code adds null characters to the end of the message until it becomes a multiple of 16 bytes.
        */ 
        while (plainText.getBytes("UTF-8").length % 16 != 0){
            plainText = plainText.concat("\0");
        }

        /*
         * The plaintext message is then encrypted using the cipher object created in the encrypt function and returned as a byte array.
         */
        byte[] encPlaintext = plainText.getBytes("UTF-8");
        return cipher.doFinal(encPlaintext);
    }

    
    // a function that decrypts a cipher text using a session key
    public static String decrypt(String cipherText, BigInteger sessionKey) throws Exception {

        // Convert the cipher text to byte array
        byte[] byteText = Base64.getDecoder().decode(cipherText);

        // Convert session key to a Byte Array
        byte[] secretKey = sessionKey.toByteArray();
        secretKey = Arrays.copyOf(secretKey, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec key = new SecretKeySpec(secretKey, "AES"); 

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));

        return new String(cipher.doFinal(byteText), "UTF-8");

    }

    public static Object[] genRandom() throws IOException {

        SecureRandom sr = new SecureRandom();
        BigInteger q = new BigInteger(keyLength, 10, sr);

        // Generate your secret exponent
        BigInteger a = new BigInteger(keyLength - 1, sr);
        BigInteger xa = new BigInteger(keyLength - 1, sr);

        // Raise a to this power
        BigInteger ya = a.modPow(xa, q);

        return new Object[] { q, a, xa, ya };

    }


    public static void main(String[] args) throws Exception {

        // Generate a secure random prime numbers
        Object[] randomPrimes = genRandom();

        Arrays.toString(randomPrimes);
        int i = 0;
        BigInteger q = (BigInteger) randomPrimes[i];
        BigInteger a = (BigInteger) randomPrimes[i + 1];
        BigInteger xa = (BigInteger) randomPrimes[i + 2];
        BigInteger ya = (BigInteger) randomPrimes[i + 3];

        // Open a connection with a server waiting for info
        System.out.println("Enter host name or IP address of server:");
        String host = userResponse.readLine();

        // Server should be listening on port 11111
        Socket link = new Socket(host, 11111);

        // Open input and output streams on the socket
        BufferedReader in = new BufferedReader(new InputStreamReader(link.getInputStream()));
        PrintStream out = new PrintStream(link.getOutputStream());

        // Send the values q, a, y to server
        out.println(q);
        out.println(a);
        out.println(ya);

        // Get the yb value from server
        BigInteger yb = new BigInteger(in.readLine());

        // Raise yb to xa power-this is the secret key
        BigInteger key = yb.modPow(xa, q);

    
        System.out.println("The secret key generated is: \n" + key);

        // receive message from user
        System.out.println("Enter a message you want to encrypt and send to the server:");
        String message = userResponse.readLine();

        // encrypt the message and change it to byte array
        byte[] cipherArray = encrypt(message, key);

        // encode the byte array to a string
        String cipherText = Base64.getEncoder().withoutPadding().encodeToString(cipherArray);
        System.out.println("\nThe encrypted message that is sent to the server is: \n" + cipherText + "\n\n");
        System.out.println("Waiting for the server's replay \n");

        // Send the encrypted message to the server
        out.println(cipherText);

        // communication between client and server
        
        String serverResponse = "";
        do {
            serverResponse = in.readLine();

            if (serverResponse == null)
            {   
                System.out.println("The server has terminated the communication");
                return;
            }
            System.out.println("The server's encrypted response is: " + serverResponse + "\n");
            System.out.println("The server's decrypted response is: " + decrypt(serverResponse, key));
            System.out.println("\nDo you want to send a replay? if you do enter 'Y', else enter any character: ");

            // read users response
            String choice = userResponse.readLine();
            if (choice.equals("Y") || choice.equals("y")) {
                System.out.println("Enter the replay message: ");
    
                String clientReplay = userResponse.readLine();

                // encrypt the client replay and change it to a byte array
                byte[] byteReplay = encrypt(clientReplay, key);

                // send the replay to the server
                out.println(Base64.getEncoder().withoutPadding().encodeToString(byteReplay));

            } else {
                System.out.println("You have terminated the communication!!!");
                return;
            }
        } while (!serverResponse.isEmpty());

        userResponse.readLine();

    }

}