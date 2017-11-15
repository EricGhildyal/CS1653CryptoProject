import java.io.*;
import org.json.*;
import java.util.Random;
import java.util.Scanner;
import org.apache.commons.codec.binary.Base64;

public class UserPasswordDB{
  String filename = "";
  CryptoHelper crypto;

  public UserPasswordDB(String filename){
    this.filename = filename;
    crypto = new CryptoHelper();
  }

  public synchronized void add(String user, String password) throws Exception{
    if(get(user)){
      throw new Exception("User already exists in database!");
    }
    else{
      FileWriter fWriter = new FileWriter(filename, true);
      try{
        byte[] r = new byte[32]; //Means 256 bit
        Random rand = new Random();
        rand.nextBytes(r);
        String salt = Base64.encodeBase64String(r);
        String saltedPass = salt+password;
        password = crypto.sha256(saltedPass);

        String obj = String.format("{\"user\":\"%s\",\"password\":\"%s\",\"salt\":\"%s\"}\n", user, password, salt);
        fWriter.write(obj);
        fWriter.close();
      }
      catch(IOException e){
          fWriter.close();
          e.printStackTrace();
      }
    }
  }

  public synchronized void remove(String user) throws Exception{
    if(!get(user)){
      throw new Exception("User does not exist in database!");
    }
    else{
      File tempFile = new File("tempDB.txt");
      File dbFile = new File(filename);
      BufferedReader reader = new BufferedReader(new FileReader(filename));
      BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));

      String currentLine ="";
      while((currentLine = reader.readLine()) != null) {
        JSONObject jobj = new JSONObject(currentLine);
        String storedUser = jobj.getString("user");
        if(user.equals(storedUser)){
          continue;
        }
        writer.write(currentLine + "\n");
      }
      writer.close();
      reader.close();
      tempFile.renameTo(dbFile);
    }
  }

  public synchronized boolean get(String user, String password){
    File inputFile = new File(filename);
    Scanner fileReader;
    try{
      fileReader = new Scanner(inputFile);
    }catch(Exception e){
      e.printStackTrace();
      return false;
    }

    String line = "";
    try{
      while(fileReader.hasNextLine()){
        line = fileReader.nextLine();
        JSONObject jobj = new JSONObject(line);
        String storedUser = jobj.getString("user");
        String storedPass = jobj.getString("password");

        if(user.equals(storedUser)){
          String saltedPass = jobj.getString("salt") + password;
          password = crypto.sha256(saltedPass);
          if(password.equals(storedPass)){
            fileReader.close();
            return true;
          }
        }
      }
    }catch(JSONException e){
      e.printStackTrace();
      fileReader.close();
      return false;
    }
    fileReader.close();
    return false;
  }

  public synchronized boolean get(String user){
    File inputFile = new File(filename);
    Scanner fileReader;

    try{
      fileReader = new Scanner(inputFile);
    }catch(Exception e){
      e.printStackTrace();
      return false;
    }

    String line = "";

    try{
      while(fileReader.hasNextLine()){
        line = fileReader.nextLine();
        JSONObject jobj = new JSONObject(line);
        String storedUser = jobj.getString("user");

        if(user.equals(storedUser)){
          fileReader.close();
          return true;
        }
      }
    }catch(JSONException e){
      e.printStackTrace();
      fileReader.close();
      return false;
    }
    fileReader.close();
    return false;
  }
}
