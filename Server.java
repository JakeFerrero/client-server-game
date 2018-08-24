import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.Random;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.GeneralSecurityException;
import javax.xml.bind.DatatypeConverter;

/**
 * @author Jake Ferrero (jaferrer)
 * A server that keeps up with a public key for every user, along
 * with a map with a location for every user.
 */
public class Server {
  
  /** Port number used by the server */
  public static final int PORT_NUMBER = 26034;
  
  /**
   * Synchronization object to let other threads know that this one is currently
   * working on the map
   */
  private Object working = new Object();
  
  /** Boolean depicting whether the thread is working */
  private boolean isWorking = false;
  
  /**
   * Inner class that extends a thread.  This inner thread class will be used by the outer class
   * when it needs to create threads.  This inner thread class can take parameters for its
   * constructor to keep up with things such as what number thread it is.
   * @author Jake Ferrero (jaferrer)
   */
  private class MyThread extends Thread {
    // Socket
    private Socket sock;
    
    // Constructor for the MyThread class
    public MyThread(Socket sock) {
      this.sock = sock;
    }
    
    // Run method for the class
    public void run() {
      handleClient(this.sock); 
    }
  }

  /** Record for an individual user. */
  private static class UserRec {
    // Name of this user.
    String name;

    // This user's public key.
    PublicKey publicKey;
    
    // Location for this user.
    int row = -1;
    int col = -1;
  }

  /** List of all the user records. */
  private ArrayList< UserRec > userList = new ArrayList< UserRec >();

  /** Current map, a 2D array of characters. */
  private char map[][];

  /** Read the map and all the users, done at program start-up. */
  private void readMap() throws Exception {
    Scanner input = new Scanner( new File( "map.txt" ) );

    // Read in the map.
    int height = input.nextInt();
    int width = input.nextInt();

    map = new char [ height ][];
    for ( int i = 0; i < height; i++ )
      map[ i ] = input.next().toCharArray();

    // Read in all the users.
    int userCount = input.nextInt();
    for ( int k = 0; k < userCount; k++ ) {
      // Create a record for the next user.
      UserRec rec = new UserRec();
      rec.name = input.next();
      
      // Get the key as a string of hex digits and turn it into a byte array.
      String hexKey = input.nextLine().trim();
      byte[] rawKey = DatatypeConverter.parseHexBinary( hexKey );
    
      // Make a key specification based on this key.
      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( rawKey );

      // Make an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      rec.publicKey = keyFactory.generatePublic( pubKeySpec );

      // Make sure this user has a unique initial.
      for ( int i = 0; i < userList.size(); i++ )
        if ( rec.name.charAt( 0 ) == userList.get( i ).name.charAt( 0 ) )
          throw new Exception( "Duplicate user initials" );
      
      // Find this user on the map.
      for ( int i = 0; i < map.length; i++ )
        for ( int j = 0; j < map[ i ].length; j++ )
          if ( map[ i ][ j ] == rec.name.charAt( 0 ) ) {
            rec.row = i;
            rec.col = j;
          }
      
      if ( rec.row < 0 )
        throw new Exception( "User is not on the map" );

      // Add this user to the list of all users.
      userList.add( rec );
    }
  }

  /** Utility function to read a length then a byte array from the
      given stream.  TCP doesn't respect message boundaries, but this
      is essentially a technique for marking the start and end of
      each message in the byte stream.  This can also be used by the
      client. */
  public static byte[] getMessage( DataInputStream input ) throws IOException {
    int len = input.readInt();
    byte[] msg = new byte [ len ];
    input.readFully( msg );
    return msg;
  }

  /** Function analogous to the previous one, for sending messages. */
  public static void putMessage( DataOutputStream output, byte[] msg ) throws IOException {
    // Write the length of the given message, followed by its contents.
    output.writeInt( msg.length );
    output.write( msg, 0, msg.length );
    output.flush();
  }

  /** Function to handle interaction with a client.  Really, this should
      be run in a thread. */
  public void handleClient( Socket sock ) {
    try {
      // Get formatted input/output streams for this thread.  These can read and write
      // strings, arrays of bytes, ints, lots of things.
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );
      DataInputStream input = new DataInputStream( sock.getInputStream() );
      
      // Get the username.
      String username = input.readUTF();

      // Make a random sequence of bytes to use as a challenge string.
      Random rand = new Random();
      byte[] challenge = new byte [ 16 ];
      rand.nextBytes( challenge );

      // Make a session key for communiating over AES.  We use it later, if the
      // client successfully authenticates.
      byte[] sessionKey = new byte [ 16 ];
      rand.nextBytes( sessionKey );

      // Find this user.  We don't need to synchronize here, since the set of users never
      // changes.
      UserRec rec = null;
      for ( int i = 0; rec == null && i < userList.size(); i++ )
        if ( userList.get( i ).name.equals( username ) )
          rec = userList.get( i );

      // Did we find a record for this user?
      if ( rec != null ) {
        // We need this to make sure the client properly encrypted
        // the challenge.
        Cipher RSADecrypter = Cipher.getInstance( "RSA" );
        RSADecrypter.init( Cipher.DECRYPT_MODE, rec.publicKey );
          
        // And this to send the session key 
        Cipher RSAEncrypter = Cipher.getInstance( "RSA" );
        RSAEncrypter.init( Cipher.ENCRYPT_MODE, rec.publicKey );
        
        byte[] encryptedChallenge;
        // Send the client the challenge.
        putMessage( output, challenge );
        
        // Get back the client's encrypted challenge.
        encryptedChallenge = getMessage(input);
        
        // Make sure the client properly encrypted the challenge.
        byte[] decodedChallenge = RSADecrypter.doFinal(encryptedChallenge);
        // If the decoded challenge string doesn't match the original, the user has failed
        // authentication and we should close the socket
        if (!Arrays.equals(decodedChallenge, challenge)) {
          try {
            // Close the socket
            sock.close();
          } catch ( Exception e ) {
          }
        }

        // Send the client the session key (encrypted)
        byte[] encryptedKey = RSAEncrypter.doFinal(sessionKey);
        putMessage(output, encryptedKey);

        // Make AES cipher objects to encrypt and decrypt with
        // the session key.
        SecretKey newKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        Cipher AESDecrypter = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
        AESDecrypter.init( Cipher.DECRYPT_MODE, newKey );
        Cipher AESEncrypter = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
        AESEncrypter.init( Cipher.ENCRYPT_MODE, newKey );
        
        byte[] requestBytes;
        // Get the first client request
        requestBytes = AESDecrypter.doFinal(getMessage( input ));
        String request = new String( requestBytes );

        // All request are single words, easy to dispatch based on the request.
        while ( ! request.equals( "exit" ) ) {
          // Create a reply string
          StringBuilder reply = new StringBuilder(); 
          
          if (!request.equals("map") && !request.equals("right") && !request.equals("left")
              && !request.equals("up") && !request.equals("down")) {
            reply.append("Invalid command\n");
            
            // Encode the reply
            byte[] encodedReply = AESEncrypter.doFinal(reply.toString().getBytes());
            
            // Send the reply back to our client.
            putMessage( output, encodedReply );
           
            // Get the next command.
            requestBytes = AESDecrypter.doFinal(getMessage( input ));
            
            request = new String( requestBytes );
            
            // continue with the while loop
            continue;
          }  
          
          synchronized (working) {
            try {
              while (isWorking) { working.wait(); }
              isWorking = true;

              // If the request was "map" then send a reply that is a string representation of the map
              if (request.equals("map")) {
                for(int i = 0; i < map.length; i++) {
                  for (int j = 0; j < map[0].length; j++) {
                    reply.append(map[i][j]);
                  }
                  reply.append("\n");
                }
              }

              // Else the request is one of the move requests (or invalid)
              else {
                // Create a buffered writer so we can write to the log file
                BufferedWriter logFile = new BufferedWriter(new FileWriter(new File("log.txt"), true));

                // The request was a "right" command...
                if (request.equals("right")) {
                  String r = right(rec);
                  reply.append(r);
                }

                // The request was a "left" command...
                else if (request.equals("left")) {
                  String r = left(rec);
                  reply.append(r);
                }

                // The request was a "up" command...
                else if (request.equals("up")) {
                  String r = up(rec);
                  reply.append(r);
                }

                // The request was a "down" command...
                else if (request.equals("down")) {
                  String r = down(rec);
                  reply.append(r);
                }
                // Write to the log file
                logFile.append(rec.name + " " + request + "\n");
                logFile.flush();
              }

              // This thread is no longer working in the map, so let the other threads know
              isWorking = false;
              working.notifyAll();
            } catch (InterruptedException e) {}
          }
 
          // Encode the reply
          byte[] encodedReply = AESEncrypter.doFinal(reply.toString().getBytes());
          
          // Send the reply back to our client.
          putMessage( output, encodedReply );
          
          // Get the next command.
          requestBytes = AESDecrypter.doFinal(getMessage( input ));
          request = new String( requestBytes );
        }
      }
    } catch ( IOException e ) {
      System.out.println( "IO Error: " + e );
    } catch( GeneralSecurityException e ){
      System.err.println( "Encryption error: " + e );
    } finally {
      try {
        // Close the socket on the way out.
        sock.close();
      } catch ( Exception e ) {
      }
    }
  }

  /**
   * Method for moving a user one space to the right.
   * The player will be blocked if there is an obstacle in front of them, or if there are
   * no spaces left to move to in front of them.  A player can push a boulder in the direction
   * they are moving only if there is a free space behind the boulder.  Updates the map the player
   * is on and then returns a string that describes the move.
   * @param rec User's record
   * @return OK if the moved successfully, Blocked if they were blocked
   */
  private String right(UserRec rec) {
    StringBuilder reply = new StringBuilder();
    // the right-most boundary of the board
    int boardRightBoundary = map[0].length - 1;
    
   // Are we at the right-side boundary?
    if (rec.col == boardRightBoundary) {
      reply.append("Blocked\n");
    }
    // Is the space in front of the player free?
    else if (map[rec.row][rec.col + 1] == '.') {
      // update the map
      map[rec.row][rec.col] = '.';
      map[rec.row][rec.col + 1] = rec.name.charAt(0);
      rec.col += 1;
      reply.append("OK\n");
    }
    // Is there a boulder in front of the player?
    else if (map[rec.row][rec.col + 1] == '*') {
      // If there is, is there even a space after the boulder?
      if (rec.col + 1 == boardRightBoundary) {
        reply.append("Blocked\n");
      }
      // Ok, there was a space, but is that space after the boulder free?
      else if (map[rec.row][rec.col + 2] == '.') {
        // update the map
        map[rec.row][rec.col] = '.';
        map[rec.row][rec.col + 1] = rec.name.charAt(0);
        map[rec.row][rec.col + 2] = '*';
        rec.col += 1;
        reply.append("OK\n");
      }
      // else, we are blocked
      else {
        reply.append("Blocked\n");
      }
    }
    // Anything else in front of the player means we are blocked
    else {
      reply.append("Blocked\n");
    }
    
    // return the reply
    return reply.toString();
  }
  
  /**
   * Method for moving a user one space to the left.
   * The player will be blocked if there is an obstacle in front of them, or if there are
   * no spaces left to move to in front of them.  A player can push a boulder in the direction
   * they are moving only if there is a free space behind the boulder.  Updates the map the player
   * is on and then returns a string that describes the move.
   * @param rec User's record
   * @return OK if the moved successfully, Blocked if they were blocked
   */
  private String left(UserRec rec) {
    StringBuilder reply = new StringBuilder();
    
    // Are we at the left-side boundary?
    if (rec.col == 0) {
      reply.append("Blocked\n");
    }
    // Is the space in front of the player free?
    else if (map[rec.row][rec.col - 1] == '.') {
      // update the map
      map[rec.row][rec.col] = '.';
      map[rec.row][rec.col - 1] = rec.name.charAt(0);
      rec.col -= 1;
      reply.append("OK\n");
    }
    // Is there a boulder in front of the player?
    else if (map[rec.row][rec.col - 1] == '*') {
      // If there is, is there even a space after the boulder?
      if (rec.col - 1 == 0) {
        reply.append("Blocked\n");
      }
      // Ok, there was a space, but is that space after the boulder free?
      else if (map[rec.row][rec.col - 2] == '.') {
        // update the map
        map[rec.row][rec.col] = '.';
        map[rec.row][rec.col - 1] = rec.name.charAt(0);
        map[rec.row][rec.col - 2] = '*';
        rec.col -= 1;
        reply.append("OK\n");
      }
      // else, we are blocked
      else {
        reply.append("Blocked\n");
      }
    }
    // Anything else in front of the player means we are blocked
    else {
      reply.append("Blocked\n");
    }
    
    return reply.toString();
  }
  
  /**
   * Method for moving a user one space up.
   * The player will be blocked if there is an obstacle in front of them, or if there are
   * no spaces left to move to in front of them.  A player can push a boulder in the direction
   * they are moving only if there is a free space behind the boulder.  Updates the map the player
   * is on and then returns a string that describes the move.
   * @param rec User's record
   * @return OK if the moved successfully, Blocked if they were blocked
   */
  private String up(UserRec rec) {
    StringBuilder reply = new StringBuilder();
    
    // Are we at the top boundary?
    if (rec.row == 0) {
      reply.append("Blocked\n");
    }
    // Is the space in front of the player free?
    else if (map[rec.row - 1][rec.col] == '.') {
      // update the map
      map[rec.row][rec.col] = '.';
      map[rec.row - 1][rec.col] = rec.name.charAt(0);
      rec.row -= 1;
      reply.append("OK\n");
    }
    // Is there a boulder in front of the player?
    else if (map[rec.row - 1][rec.col] == '*') {
      // If there is, is there even a space after the boulder?
      if (rec.row - 1 == 0) {
        reply.append("Blocked\n");
      }
      // Ok, there was a space, but is that space after the boulder free?
      else if (map[rec.row - 2][rec.col] == '.') {
        // update the map
        map[rec.row][rec.col] = '.';
        map[rec.row - 1][rec.col] = rec.name.charAt(0);
        map[rec.row - 2][rec.col] = '*';
        rec.row -= 1;
        reply.append("OK\n");
      }
      // else, we are blocked
      else {
        reply.append("Blocked\n");
      }
    }
    // Anything else in front of the player means we are blocked
    else {
      reply.append("Blocked\n");
    }
    
    return reply.toString();
  }
  
  /**
   * Method for moving a user one space down.
   * The player will be blocked if there is an obstacle in front of them, or if there are
   * no spaces left to move to in front of them.  A player can push a boulder in the direction
   * they are moving only if there is a free space behind the boulder.  Updates the map the player
   * is on and then returns a string that describes the move.
   * @param rec User's record
   * @return OK if the moved successfully, Blocked if they were blocked
   */
  private String down(UserRec rec) {
    StringBuilder reply = new StringBuilder();
    // the bottom boundary of the board
    int boardBottomBoundry = map.length - 1;
    
    // Are we at the bottom boundary?
    if (rec.row == boardBottomBoundry) {
      reply.append("Blocked\n");
    }
    // Is the space in front of the player free?
    else if (map[rec.row + 1][rec.col] == '.') {
      // update the map
      map[rec.row][rec.col] = '.';
      map[rec.row + 1][rec.col] = rec.name.charAt(0);
      rec.row += 1;
      reply.append("OK\n");
    }
    // Is there a boulder in front of the player?
    else if (map[rec.row + 1][rec.col] == '*') {
      // If there is, is there even a space after the boulder?
      if (rec.row + 1 == boardBottomBoundry) {
        reply.append("Blocked\n");
      }
      // Ok, there was a space, but is that space after the boulder free?
      else if (map[rec.row + 2][rec.col] == '.') {
        // update the map
        map[rec.row][rec.col] = '.';
        map[rec.row + 1][rec.col] = rec.name.charAt(0);
        map[rec.row + 2][rec.col] = '*';
        rec.row += 1;
        reply.append("OK\n");
      }
      // else, we are blocked
      else {
        reply.append("Blocked\n");
      }
    }
    // Anything else in front of the player means we are blocked
    else {
      reply.append("Blocked\n");
    }
    
    return reply.toString();
  }
  
  /** Essentially, the main method for our server, as an instance method
      so we can access non-static fields. */
  private void run( String[] args ) {
    ServerSocket serverSocket = null;
    
    // One-time setup.
    try {
      // Read the map and the public keys for all the users.
      readMap();
      for(int i = 0; i < map.length; i++) {
        for (int j = 0; j < map[0].length; j++) {
          System.out.print(map[i][j]);
        }
        System.out.println();
      }

      // Create the log file
      File log = new File("log.txt");
      // if it exists, then we need to read from the file before we accept client requests
      if (log.exists()) {
        Scanner logger = new Scanner(log);
        while (logger.hasNextLine()) {
          String s = logger.nextLine();
          Scanner line = new Scanner(s);
          String user = line.next();
          // Find this user.
          UserRec rec = null;
          for ( int i = 0; rec == null && i < userList.size(); i++ )
            if ( userList.get( i ).name.equals( user ) )
              rec = userList.get( i );
          
          // Get the command that user ran and run the corresponding method
          String command = line.next();
          if (command.equals("right")) {
            right(rec);
          }
          else if (command.equals("left")) {
            left(rec);
          }
          else if (command.equals("up")) {
            up(rec);
          }
          else if (command.equals("down")){
            down(rec);
          }
          else {}
        }       
      }
      
      // Open a socket for listening.
      serverSocket = new ServerSocket( PORT_NUMBER );
    } catch( Exception e ){
      System.err.println( "Can't initialize server: " + e );
      System.exit( 1 );
    }
     
    // Keep trying to accept new connections and serve them.
    while( true ){
      try {
        // Try to get a new client connection.
        Socket sock = serverSocket.accept();

        // Handle interaction with this client.
        // Each client has their own thread.
        MyThread thread = new MyThread(sock);
        // Start the thread.
        thread.start();
        
      } catch( IOException e ){
        System.err.println( "Failure accepting client " + e );
      }
    }
  }

  /**
   * Main method.  Calls the run function for the server.
   * @param args Command-line arguments
   */
  public static void main( String[] args ) {
    // Make a server object, so we can have non-static fields.
    Server server = new Server();
    server.run( args );
  }
}
