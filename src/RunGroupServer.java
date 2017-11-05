/* Driver program for FileSharing Group Server */

public class RunGroupServer {

	public static void main(String[] args) {
		if (args.length > 1) {
			try {
				GroupServer server = new GroupServer(Integer.parseInt(args[0]), args[1]);
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", GroupServer.SERVER_PORT);
			}
		}
		else if (args.length > 0){
			GroupServer server = new GroupServer(args[0]);
			server.start();
		}
		else{
			System.out.println("Error - Usage: java RunGroupServer [port] <database_filename>");
		}
	}
}
