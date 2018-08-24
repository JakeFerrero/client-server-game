import java.io.*;
import java.util.Scanner;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.GeneralSecurityException;
import javax.xml.bind.DatatypeConverter;

/**
 * @author Jake Ferrero (jaferrer)
 * Client supporting simple interaction with the server.
 */
public class Client {
  
  /**
   * Main method.  Connects to the server and then takes commands provided by the user
   * and sends them to the server.  Depending on the command, the client will receive
   * a certain response back from the server and then print it out to the user.  Then
   * it will prompt the user for the next command (until "exit" is entered).
   * @param args Command-line arguments
   */
  public static void main( String[] args ) {
    // Complain if we don't get the right number of arguments. 
    if ( args.length != 1 ) {
      System.out.println( "Usage: Client <host>" );
      System.exit( -1 );
    }

    try {
      // Try to create a socket connection to the server.
      Socket sock = new Socket( args[ 0 ], Server.PORT_NUMBER );

      // Get formatted input/output streams for talking with the server.
      DataInputStream input = new DataInputStream( sock.getInputStream() );
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );

      // Get a username from the user and send it to the server.
      Scanner scanner = new Scanner( System.in );
      System.out.print( "Username: " );
      String name = scanner.nextLine();
      output.writeUTF( name );
      output.flush();

      // Try to read the user's private key.
      Scanner keyScanner = new Scanner( new File( name + ".txt" ) );
      String hexKey = keyScanner.nextLine();
      byte[] rawKey = DatatypeConverter.parseHexBinary( hexKey );
      keyScanner.close();
    
      // Make a key specification based on this key.
      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( rawKey );
      
      // Get an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      PrivateKey privateKey = keyFactory.generatePrivate( privKeySpec );

      // Make a cipher object that will encrypt using this key.
      Cipher RSAEncrypter = Cipher.getInstance( "RSA" );
      RSAEncrypter.init( Cipher.ENCRYPT_MODE, privateKey );

      // Make another cipher object that will decrypt using this key.
      Cipher RSADecrypter = Cipher.getInstance( "RSA" );
      RSADecrypter.init( Cipher.DECRYPT_MODE, privateKey );

      // Get the challenge string (really a byte array) from the server.
      byte[] challenge = Server.getMessage( input );

      // Encrypt the challenge with our private key and send it back.
      byte[] encryptedChallenge = RSAEncrypter.doFinal(challenge);
      Server.putMessage(output, encryptedChallenge);

      // Get the symmetric key from the server and make AES
      // encrypt/decrypt objects for it.
      byte[] encryptedKey = Server.getMessage(input);
      byte[] decodedKey = RSADecrypter.doFinal(encryptedKey);
      SecretKey sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
      
      // Create an instance of an AES Decrypter and Encrypter using the session key
      // provided by the server.
      Cipher AESDecrypter = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
      AESDecrypter.init( Cipher.DECRYPT_MODE, sessionKey );
      Cipher AESEncrypter = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
      AESEncrypter.init( Cipher.ENCRYPT_MODE, sessionKey );

      // Read commands from the user and print server responses.
      String request = "";
      System.out.print( "cmd> " );
      while ( scanner.hasNextLine() && ! ( request = scanner.nextLine() ).equals( "exit" ) ) {
        // encrypt the request, then send it
        byte[] encryptedCommand = AESEncrypter.doFinal(request.getBytes());
        Server.putMessage( output, encryptedCommand );

        // decrypt the response and then print it
        byte[] encodedResponse = Server.getMessage( input );
        byte[] responseBytes = AESDecrypter.doFinal(encodedResponse);
        String response = new String(responseBytes);
        System.out.print( response );
        
        // Print next command line
        System.out.print( "cmd> " );
      }
      
      // Send the exit command to the server.
      byte[] encryptedCommand = AESEncrypter.doFinal(request.getBytes());
      Server.putMessage( output, encryptedCommand );
 
      // We are done communicating with the server.
      sock.close();
    } catch( IOException e ){
      System.err.println( "IO Error: " + e );
    } catch( GeneralSecurityException e ){
      System.err.println( "Encryption error: " + e );
    }
  }
}
