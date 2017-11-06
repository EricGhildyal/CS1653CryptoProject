public class TokenTuple {
  public UserToken tok;
  public byte[] hashedToken;

  public TokenTuple(UserToken tok, byte[] hashedToken){
    this.tok = tok;
    this.hashedToken = hashedToken;
  }
}
