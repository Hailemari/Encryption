/*
 * A server side program to encrypt and decrypt a message using a symmetric session key generated and 
 * shared by DH and using AES algorithm
 */


import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Arrays;
import java.math.*;
import java.net.*;
import java.io.*;



public class DHServer {


    static final BufferedReader userResponse=new BufferedReader(new InputStreamReader(System.in));

    // initialize an initialization vector 
    static String IV = "CFQSPABSYUZXLGME";

    // A function that encrypts a plaintext message
    public static byte[] encrypt(String plainText, BigInteger sessionKey) throws Exception {

        //Convert the session key to byte array
        byte[] secretKey = sessionKey.toByteArray();


        secretKey = Arrays.copyOf(secretKey, 16);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec key = new SecretKeySpec(secretKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
        
        
        /* 
        * ensure that the plaintext message is a multiple of 16 bytes as the AES algorithm works with blocks of 16 bytes
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


    // A function that decrypts a cipher text
    public static String decrypt(String cipherText, BigInteger sessionKey) throws Exception{

        // Convert the encrypted message to a byte array
        byte[] byteText = Base64.getDecoder().decode(cipherText);

        // Convert the session key to Byte Array
        byte[] secretKey= sessionKey.toByteArray();
        secretKey = Arrays.copyOf(secretKey, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        SecretKeySpec key = new SecretKeySpec(secretKey,"AES"); 

        cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));

        return new String(cipher.doFinal(byteText),"UTF-8");

    } 

    public static void main(String[] args) throws Exception {

            //Start by listening on port 11111
            ServerSocket ss = new ServerSocket(11111);

            //Wait for a connection
            System.out.println("Waiting for the client to establish a connection... \n");
            Socket link=ss.accept();
            System.out.println("Connected!!!");
            

            //Open input and output streams on the socket
            BufferedReader in=new BufferedReader(new InputStreamReader(link.getInputStream()));
            PrintStream out=new PrintStream(link.getOutputStream());

            //Get q, a, ya values from client
            BigInteger q= new BigInteger(in.readLine());
            BigInteger a= new BigInteger(in.readLine());
            BigInteger ya=new BigInteger(in.readLine());
            
            //Produce our own secret exponent
            SecureRandom sr=new SecureRandom();
            BigInteger xb=new BigInteger(q.bitLength()-1,sr);

            //Raise a to this power
            BigInteger yb=a.modPow(xb,q);

            //Send this to client
            out.println(yb);

            //Raise ya to xb power-this is the secret key
            BigInteger sessionKey=ya.modPow(xb,q);
            System.out.println ("The secret key with "+ link.getInetAddress().toString()+" is: \n" + sessionKey + "\n");

            //Get cipher text from the client
            String encryptedMessage = in.readLine();
            System.out.println("You have received an encrypted message from the client: " + encryptedMessage + "\n");
        
            // Decrypt cipher text obtained
            String plainTextMessage = decrypt(encryptedMessage, sessionKey);
            System.out.println("The decrypted message is: " + plainTextMessage + "\n");


        
            // communication between the server and the client
            String clientMessage = "";
            
            do {
                System.out.println ("Do you want to respond to the client? enter 'Y' if you want, else enter any character: ");
               
                String userChoice = userResponse.readLine();

                if(userChoice.equals("y") || userChoice.equals("Y")){
                    System.out.println ("Enter the message you want to send to the client: ");
                    
                    
                    // read a reply from the user
                    String reply = userResponse.readLine();

                    // encrypt the reply and change it to byte array
                    byte[] byteReply = encrypt(reply, sessionKey);

                    // send to the client
                    out.println(Base64.getEncoder().encodeToString(byteReply));
                
                    
                    // receive a message from the client
                    clientMessage = in.readLine();
                    if(clientMessage == null)
                    {
                        System.out.println("The client has terminated the communication!!!");
                        return;
                    }
                    System.out.println("\nThe client responded this encrypted message: " + clientMessage + "\n");

                    // decrypt the response from the client
                    System.out.println("The client's decrypted message is: " + decrypt(clientMessage,sessionKey) + "\n");
                
                }
                else{
                    System.out.println("You have terminated the communication!!!");
                    return;
                }
            } while (!clientMessage.isEmpty());
        

            int c = System.in.read();
            userResponse.readLine();
    }

}