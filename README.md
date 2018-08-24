# Client/Server Game
A basic "game" built in Java that utilizes the client/server model, threads, and user authentication. The server creates the game map using a map file and then keeps the map's state. Clients can connect to the server and move around on the map, and changes to the map will be reflected to all other clients playing. User authentication occurs when a user attempts to log in. A challenge is sent to the client, which is encrypted using a user key file. If the encrypted challenge sent back to the server does not match the original, authentication fails.

Players may move up, down, left, or right, and the map will be reflected based on the players' movements. For example, if Elizabeth moves left, then if Francis views the map, Elizabeth's new location will be displayed. Players' movements will be blocked if there is a "wall" or another player in their way. A player can move a boulder ('*') only if there is an available space after the boulder.

If the program is stopped on the server, clients will no longer be able to connect. The server creates a log file containing all previous moves by all players. If the log file is not deleted and the server is started back up, it will read from the log file and arrange the map as it was before the application was stopped.
  
## Usage
On the Server:
```
java Server
```
On the Client:
```
java Client <host>
```
Where <host> is either localhost (if the server machine is the same as the client machine) or a valid hostname.
Once connected, you will be prompted for a username. Enter one of the usernames tied to the valid key files (for example, type "elizabeth" whose key file is elizabeth.txt to play as 'e', Elizabeth).

Valid Commands:
* "up" - Move player up.
* "down" - Move player down.
* "left" - Move player left.
* "right" - Move player right.
* "map" - Display the updated map.
