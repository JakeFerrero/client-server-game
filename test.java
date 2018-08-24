
public class test {
  public static char[][] table = new char[3][3];
  
  public static void main(String args[]) {
    
    table[0][0] = '1';
    table[0][1] = '2';
    table[0][2] = '3';
    table[1][0] = '4';
    table[1][1] = '5';
    table[1][2] = '6';
    table[2][0] = '7';
    table[2][1] = '8';
    table[2][2] = '9';
    
    StringBuilder reply = new StringBuilder();
    for(int i = 0; i < table.length; i++) {
      for (int j = 0; j < table[0].length; j++) {
        reply.append(table[i][j]);
      }
      reply.append("\n");
    }
    System.out.println(reply);  
  }
}
