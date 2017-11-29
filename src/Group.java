import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.security.*;
import java.util.*;

class Group implements Serializable{
	public ArrayList<String> memberList;
	public String name;
	public String owner;
	private int currKeyVersion;
	private HashMap<Integer,Key> groupKeyMap;
	static final long serialVersionUID = 7823049212321412923L;

	public Group(ArrayList<String> memberList, String name, String owner) {
		this.memberList = memberList;
		this.name = name;
		this.owner = owner;
		this.currKeyVersion = 0;
		groupKeyMap = new HashMap<Integer, Key>();
		Key k = getNewKey();
		groupKeyMap.put(new Integer(0), k);
	}

	private Key getNewKey(){
		CryptoHelper crypto = new CryptoHelper();
		return crypto.getNewAESKey();
	}

	//when we need to add a new key
	//increment key version by one and store it
	public Key addKey(){
		CryptoHelper crypto = new CryptoHelper();
		Key newKey = crypto.getNewAESKey();
		this.currKeyVersion++;
		groupKeyMap.put(new Integer(this.currKeyVersion), newKey);
		return newKey;
	}

	public int getCurrKeyVersion(){
		return this.currKeyVersion;
	}

	public Key getKeyAtVersion(int version){
		if(version > this.currKeyVersion){
			return null;
		}
		return groupKeyMap.get(new Integer(version));
	}

	public String toString(){
		return name;
	}
}