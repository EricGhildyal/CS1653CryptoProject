
import java.util.List;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken
{
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
    public String getIssuer();

    /**
     * This method should return a byte array containing the public key of the
     * server that this key should be user for. For instance, if Alice contacts
     * Server1 looking for a key for Server2, this will return Server2's public key,
     * as provided by Alice in her request.
     * @return The issuer of this token
     *
     */
    public byte[] getTarget();

    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();

    /**
     * This method creates a predictable string that is unique to this token.
     * It contains the server name, the user name, and the list of user groups
     * where the groups are in alphabetical order and each item is delimited by '/'
     *
     * @return A unique String for this token
     *
     */
    public String toUniqueString();

}   //-- end interface UserToken
