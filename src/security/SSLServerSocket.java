package security;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;

public class SSLServerSocket extends ServerSocket
{
  protected RSA.PrivateKey sKR;
  protected Properties prop;

  public SSLServerSocket(int paramInt1, int paramInt2, InetAddress paramInetAddress, RSA.PrivateKey paramPrivateKey, Properties paramProperties)
    throws IOException
  {
    super(paramInt1, paramInt2, paramInetAddress);
    this.sKR = paramPrivateKey;
    this.prop = paramProperties;
  }

  public SSLServerSocket(int paramInt1, int paramInt2, RSA.PrivateKey paramPrivateKey, Properties paramProperties)
    throws IOException
  {
    super(paramInt1, paramInt2);
    this.sKR = paramPrivateKey;
    this.prop = paramProperties;
  }

  public SSLServerSocket(int paramInt, RSA.PrivateKey paramPrivateKey, Properties paramProperties)
    throws IOException
  {
    super(paramInt);
    this.sKR = paramPrivateKey;
    this.prop = paramProperties;
  }

  public Socket accept()
    throws IOException
  {
    Socket localSocket = super.accept();
    byte[] arrayOfByte = null;
    Hash localHash = null;
    try {
      Object[] arrayOfObject = handshake(localSocket);
      arrayOfByte = (byte[])arrayOfObject[0];
      localHash = (Hash)arrayOfObject[1];
    } catch (Exception localException) {
      throw new IOException(localException.toString());
    }
    return new SSLSocket(localSocket, arrayOfByte, localHash);
  }

  protected byte[] getGreetingToken(Socket paramSocket)
    throws IOException
  {
    int i = 128;
    byte[] localObject = new byte[i];
    int j = 0;
    int k;
    while ((k = paramSocket.getInputStream().read()) != 33) {
      if (k == -1) {
        throw new EOFException("Unexpected end of Greeting");
      }
      if ((k == 92) && ((k = paramSocket.getInputStream().read()) == -1))
        throw new EOFException("Unexpected end of Greeting");
      if (j == i) {
        i += i / 2 + 1;
        byte[] arrayOfByte = new byte[i];
        System.arraycopy(localObject, 0, arrayOfByte, 0, j);
        localObject = arrayOfByte;
      }
      localObject[(j++)] = ((byte)k);
    }
    byte[] arrayOfByte = new byte[j];
    System.arraycopy(localObject, 0, arrayOfByte, 0, j);
    return arrayOfByte;
  }

  protected Object[] handshake(Socket paramSocket)
    throws Exception
  {
    int i;
    while ((i = paramSocket.getInputStream().read()) != 33) {
      if (i == -1) throw new EOFException("Unfinished Greeting");
    }
    byte[] arrayOfByte1 = getGreetingToken(paramSocket);
    byte[] arrayOfByte2 = getGreetingToken(paramSocket);
    byte[] arrayOfByte3 = getGreetingToken(paramSocket);

    String str1 = new String(RSA.cipher(arrayOfByte1, this.sKR));

    String str2 = this.prop.getProperty(str1 + ".public_key");

    if (str2 == null)
      throw new Exception("Unknown User: " + str1);
    RSA.PublicKey localPublicKey = new RSA.PublicKey(str2.getBytes());

    String str3 = new String(RSA.cipher(arrayOfByte2, localPublicKey));

    if (!str3.equals(this.prop.getProperty(str1 + ".company"))) {
      throw new Exception("Company ERROR (" + str1 + ':' + str3 + ")");
    }
    int j = Integer.parseInt(this.prop.getProperty(str1 + ".ndatabytes"));
    int k = Integer.parseInt(this.prop.getProperty(str1 + ".ncheckbytes"));
    byte b = (byte)Integer.parseInt(this.prop.getProperty(str1 + ".pattern"));
    int m = Integer.parseInt(this.prop.getProperty(str1 + ".k"));
    Object[] arrayOfObject = new Object[2];

    arrayOfObject[0] = RSA.cipher(arrayOfByte3, this.sKR);

    arrayOfObject[1] = new Hash(j, k, b, m);
    return arrayOfObject;
  }
}