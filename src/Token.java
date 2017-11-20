import java.util.List;
import java.util.ArrayList;
import java.util.*;
import java.security.Key;
import org.apache.commons.codec.binary.Base64;


public class Token implements UserToken{

  private String server, username;
  private ArrayList<String> groups;
  private String target;

  public Token(String server, String username, ArrayList<String> groups, Key target){
    this.server = server;
    this.username = username;
    this.groups = groups;
    this.target = Base64.encodeBase64String(target.getEncoded());
  }

  public Token(String server, String username, ArrayList<String> groups, String target){
    this.server = server;
    this.username = username;
    this.groups = groups;
    this.target = target;
  }

  /**
   * This method should return a string describing the issuer of
   * this token.  This string identifies the group server that
   * created this token.  For instance, if "Alice" requests a token
   * from the group server "Server1", this method will return the
   * string "Server1".
   *
   * @return The issuer of this token
   *
   */
  public String getIssuer(){
    return this.server;
  }

  /**
   * This method should return a byte array containing the public key of the
   * server that this key should be user for. For instance, if Alice contacts
   * Server1 looking for a key for Server2, this will return Server2's public key,
   * as provided by Alice in her request.
   * @return The issuer of this token
   *
   */
  public String getTarget(){
    return this.target;
  }

  /**
   * This method should return a string indicating the name of the
   * subject of the token.  For instance, if "Alice" requests a
   * token from the group server "Server1", this method will return
   * the string "Alice".
   *
   * @return The subject of this token
   *
   */
  public String getSubject(){
    return this.username;
  }

  /**
   * This method extracts the list of groups that the owner of this
   * token has access to.  If "Alice" is a member of the groups "G1"
   * and "G2" defined at the group server "Server1", this method
   * will return ["G1", "G2"].
   *
   * @return The list of group memberships encoded in this token
   *
   */
  public List<String> getGroups(){
    return this.groups;
  }

  public String toString() {
	 return String.format("Server:%s\n"
	  						   + "Username:%s\n"
	  						   + "Groups:%s\n"
                   + "Target:%s\n", this.server, this.username, this.groups, this.target);
  }

	public String toUniqueString() {
		ArrayList<String> orderedGroups = new ArrayList<String>();
		for(String str : this.groups){
			orderedGroups.add(str);
		}

		Collections.sort(orderedGroups);
		String groupsListString = "";
		for(String str:orderedGroups){
			groupsListString += String.format("/%s", str);
		}

		return String.format("%s/%s%s", this.server, this.username, groupsListString);
	}

}
