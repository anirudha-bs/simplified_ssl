package security;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public class SSLSocket extends Socket
{
  protected byte[] key;
  protected Hash hash;
  protected InputStream cryptoIn;
  protected OutputStream cryptoOut;
  protected Socket socket;

  public SSLSocket(String paramString, int paramInt1, InetAddress paramInetAddress, int paramInt2, byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4, Hash paramHash)
    throws IOException
  {
    super(paramString, paramInt1, paramInetAddress, paramInt2);
    handshake(paramArrayOfByte1, paramArrayOfByte2, paramArrayOfByte3);
    this.key = paramArrayOfByte4;
    this.hash = paramHash;
  }

  public SSLSocket(String paramString, int paramInt, byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4, Hash paramHash)
    throws IOException
  {
    super(paramString, paramInt);
    handshake(paramArrayOfByte1, paramArrayOfByte2, paramArrayOfByte3);
    this.key = paramArrayOfByte4;
    this.hash = paramHash;
  }

  public SSLSocket(InetAddress paramInetAddress1, int paramInt1, InetAddress paramInetAddress2, int paramInt2, byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4, Hash paramHash)
    throws IOException
  {
    super(paramInetAddress1, paramInt1, paramInetAddress2, paramInt2);
    handshake(paramArrayOfByte1, paramArrayOfByte2, paramArrayOfByte3);
    this.key = paramArrayOfByte4;
    this.hash = paramHash;
  }

  public SSLSocket(InetAddress paramInetAddress, int paramInt, byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, byte[] paramArrayOfByte4, Hash paramHash)
    throws IOException
  {
    super(paramInetAddress, paramInt);
    handshake(paramArrayOfByte1, paramArrayOfByte2, paramArrayOfByte3);
    this.key = paramArrayOfByte4;
    this.hash = paramHash;
  }

  public SSLSocket(Socket paramSocket, byte[] paramArrayOfByte, Hash paramHash)
    throws IOException
  {
    this.socket = paramSocket;
    this.key = paramArrayOfByte;
    this.hash = paramHash;
  }

  public void close()
    throws IOException
  {
    if (this.socket == null) {
      super.close();
      return;
    }
    this.socket.close();
  }

  public InputStream getCryptedInputStream()
    throws IOException
  {
    if (this.socket == null) {
      return super.getInputStream();
    }
    return super.getInputStream();
  }

  public InputStream getInputStream()
    throws IOException
  {
    if (this.cryptoIn == null) {
      InputStream localInputStream = 
        this.socket != null ? this.socket.getInputStream() : super.getInputStream();
      this.cryptoIn = new CryptoInputStream(localInputStream, this.key, this.hash);
    }
    return this.cryptoIn;
  }

  public OutputStream getOutputStream() throws IOException {
    if (this.cryptoOut == null) {
      OutputStream localOutputStream = 
        this.socket != null ? this.socket.getOutputStream() : super.getOutputStream();
      this.cryptoOut = new CryptoOutputStream(localOutputStream, this.key, this.hash);
    }
    return this.cryptoOut;
  }

  protected void handshake(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3)
    throws IOException
  {
    int i = 0;
    for (int j = 0; j < paramArrayOfByte1.length; j++) {
      if ((paramArrayOfByte1[j] == 33) || (paramArrayOfByte1[j] == 92)) i++;
    }
    for (int k = 0; k < paramArrayOfByte2.length; k++) {
      if ((paramArrayOfByte2[k] == 33) || (paramArrayOfByte2[k] == 92)) i++;
    }
    for (int m = 0; m < paramArrayOfByte3.length; m++) {
      if ((paramArrayOfByte3[m] == 33) || (paramArrayOfByte3[m] == 92)) i++;
    }
    byte[] arrayOfByte = new byte[paramArrayOfByte1.length + paramArrayOfByte2.length + paramArrayOfByte3.length + i + 4];
    int n = 1;

    arrayOfByte[0] = 33;
    for (int i1 = 0; i1 < paramArrayOfByte1.length; i1++) {
      if ((paramArrayOfByte1[i1] == 33) || (paramArrayOfByte1[i1] == 92)) arrayOfByte[(n++)] = 92;
      arrayOfByte[(n++)] = paramArrayOfByte1[i1];
    }

    arrayOfByte[(n++)] = 33;
    for (int i2 = 0; i2 < paramArrayOfByte2.length; i2++) {
      if ((paramArrayOfByte2[i2] == 33) || (paramArrayOfByte2[i2] == 92)) arrayOfByte[(n++)] = 92;
      arrayOfByte[(n++)] = paramArrayOfByte2[i2];
    }

    arrayOfByte[(n++)] = 33;
    for (int i3 = 0; i3 < paramArrayOfByte3.length; i3++) {
      if ((paramArrayOfByte3[i3] == 33) || (paramArrayOfByte3[i3] == 92)) arrayOfByte[(n++)] = 92;
      arrayOfByte[(n++)] = paramArrayOfByte3[i3];
    }

    arrayOfByte[n] = 33;
    super.getOutputStream().write(arrayOfByte);
    super.getOutputStream().flush();
  }

  public String toString()
  {
    return "Cryto(" + this.socket + ')';
  }
}