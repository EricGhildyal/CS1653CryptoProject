import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;


	/**
	 * Connects to server from param server on port param port
	 *
	 * @param server server hostname/issuer of token
	 * @param port port that server is connected to
	 * @return Whether or not the connection was sucessful or not
	 */
	public boolean connect(final String server, final int port) {
		System.out.println("attempting to connect");
		try{
			this.sock = new Socket(server, port);
		}catch(Exception e){
			System.out.println("There was an error in connecting to the server: " + e);
			return false;
		}
		return true;
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
