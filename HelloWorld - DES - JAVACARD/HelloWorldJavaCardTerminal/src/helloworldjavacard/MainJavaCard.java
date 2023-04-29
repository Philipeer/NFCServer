/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package helloworldjavacard;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


/**
 *
 * @author TexlFilip(230688)
 * @author DzurendaPetr(106420)
 */
public class MainJavaCard {

    protected List<CardTerminal> terminals;
    protected TerminalFactory factory;
    private CardTerminal terminal;
    private Card card;
    private CardChannel channel;
    private ResponseAPDU rAPDU;
    private byte[] baCommandAPDU;
    byte[] baResponceAPDU = null;
    int counter = 0;
    int KEY_LENGTH = 128;
    
    byte[] opp1 = new byte[]{(byte) 0x02};
    byte[] opp2 = new byte[]{(byte) 0x01};
    byte[] modulus = new byte[]{(byte) 0xFF};
    
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        
        MainJavaCard helloWorld = new MainJavaCard();


        try {
            helloWorld.run();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MainJavaCard.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

    }
    
    public void run() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        ObuParameters obuParameters = new ObuParameters();
        File file;
        if (KEY_LENGTH == 128){
            file = new File("obuparams128.txt");
        }
        else if (KEY_LENGTH == 256){
            file = new File("obuparams256.txt");
        }
        else{
        file = new File("obuparams.txt");}
        //if (!file.exists()) {
        //    System.out.println("The file obuparams.txt does not exist.");
        //    Client clientF = new Client();
        //    try (FileWriter writer = new FileWriter("obuparams.txt")) {
        //        writer.write(clientF.obuParameters.getDriverKey() + "\t" + clientF.obuParameters.getIdr() + "\t"
        //                + clientF.obuParameters.getKeyLengths());
        //    } catch (IOException e) {
        //        System.out.println("An error occurred while writing to the file: " + e.getMessage());
        //    }
        //}

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String[] data = reader.readLine().split("\t");
            obuParameters.setDriverKey(data[0]);
            obuParameters.setIdr(Integer.parseInt(data[1]));
            obuParameters.setKeyLengths(Integer.parseInt(data[2]));
        } catch (IOException e) {
            System.out.println("An error occurred while reading from the file: " + e.getMessage());
        }

        Cryptogram userCryptogram = new Cryptogram();
        Cryptogram receiverCryptogram = new Cryptogram();
    
         try 
    	{
            factory = TerminalFactory.getDefault();
            terminals = factory.terminals().list();
            terminal = terminals.get(0);

            System.out.println("Terminals: " + terminals);
            System.out.println("Selected Terminal: " + terminal);

           
        }catch(Exception e){
                e.printStackTrace();
        }
         
        try {	

            while (!terminal.isCardPresent()){};

            card = terminal.connect("*");
            System.out.println("ATR: "+bytesToHex(card.getATR().getBytes()));
            channel = card.getBasicChannel();

            System.out.println("\nCard info: " + card);

            }catch (CardException ce){
                ce.printStackTrace();
            }
     
        
        
        //byte[] AID = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
        //                        (byte) 0x08,
        //                        (byte) 0x4E, (byte) 0x50, (byte) 0x4F, (byte) 0x55, (byte) 0x53, (byte) 0x45, (byte) 0x52, (byte) 0x30,
        //                        (byte) 0x31}; //Tohle byl ten poslední byte totiž

        //byte[] AID = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
        //        (byte) 0x07,
        //        (byte) 0xF0, (byte) 0x39, (byte) 0x41, (byte) 0x48, (byte) 0x14, (byte) 0x81, (byte) 0x00};

        byte[] AID = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
                (byte) 0x07,
                (byte) 0xF0, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
                (byte) 0x00};

        Instant start = Instant.now();
        byte[] rData = sendAPDU(AID);

        byte[] INIT = new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03};


        //byte[] DES = new byte[]{(byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0x00,
        //                        (byte) 0x08,
        //                        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        //                       (byte) 0x08};
        
        //byte[] rDES = sendAPDU(INIT);
        receiverCryptogram.setNonce(1000);
        receiverCryptogram.setIdr(obuParameters.getIdr());
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putInt(receiverCryptogram.getNonce());
        buffer.putInt(receiverCryptogram.getIdr());
        byte[] byteArray = buffer.array();
        sendAPDU(concatenateArrays(INIT,byteArray));

        //parsování odpovědi
        if(counter == 2){
            byte[] hatuArray = new byte[(obuParameters.getKeyLengths()/4)];
            byte[] nonceArray = new byte[4];
            System.arraycopy(baResponceAPDU,0,hatuArray,0,(obuParameters.getKeyLengths()/4));
            userCryptogram.setHatu(new String(hatuArray));
            System.out.println("Parsovane hatu: " + userCryptogram.getHatu());
            System.arraycopy(baResponceAPDU,(obuParameters.getKeyLengths()/4),nonceArray,0,4);
            userCryptogram.setNonce(ByteBuffer.wrap(nonceArray).getInt());
            System.out.println("Parsovane nu: " + userCryptogram.getNonce());
            sendAPDU(new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x04});
        }

        if (counter == 3){
            byte[] ciphertext = new byte[(baResponceAPDU.length)-14];
            byte[] iv = new byte[12];
            System.arraycopy(baResponceAPDU,0,ciphertext,0,ciphertext.length);
            System.arraycopy(baResponceAPDU,ciphertext.length,iv,0,12);
            userCryptogram.setIv(iv);
            System.out.println("C1: " + Arrays.toString(ciphertext));
            System.out.println("IV: " + Arrays.toString(iv));
            CryptoCore cryptoCore = new CryptoCore(obuParameters,userCryptogram,receiverCryptogram);
            try {
                receiverCryptogram.setAuthenticated(cryptoCore.dec(ciphertext));
            }
            catch (AEADBadTagException ex) {
                receiverCryptogram.setAuthenticated(false);
            }
            Instant end = Instant.now();
            if (receiverCryptogram.isAuthenticated()){
                sendAPDU(new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x05});
            }
            else sendAPDU(new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x06});
            Duration timeElapsed = Duration.between(start,end);
            System.out.println("Time: " + timeElapsed.toMillis() + " ms");
        }
                
        
        //// Test
        //
        //Cipher ecipher;
        //byte key[] = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        //byte openText[] = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        //byte cypherText[];
        //
        //
        //try {
        //    DESKeySpec dks = new DESKeySpec(key);
        //    SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        //    SecretKey desKey = skf.generateSecret(dks);
       //
        //    ecipher = Cipher.getInstance("DES/ECB/NoPadding");
        //    ecipher.init(Cipher.ENCRYPT_MODE, desKey);
        //    cypherText =  ecipher.doFinal(openText);
        //    bytesToHex(cypherText);
        //    System.err.println(bytesToHex(cypherText));
        //} catch (NoSuchPaddingException ex) {
        //    Logger.getLogger(HelloWorldJavaCard.class.getName()).log(Level.SEVERE, null, ex);
        //} catch (InvalidKeyException ex) {
        //    Logger.getLogger(HelloWorldJavaCard.class.getName()).log(Level.SEVERE, null, ex);
        //} catch (IllegalBlockSizeException ex) {
        //    Logger.getLogger(HelloWorldJavaCard.class.getName()).log(Level.SEVERE, null, ex);
        //} catch (BadPaddingException ex) {
        //    Logger.getLogger(HelloWorldJavaCard.class.getName()).log(Level.SEVERE, null, ex);
        //} catch (InvalidKeySpecException ex) {
        //    Logger.getLogger(HelloWorldJavaCard.class.getName()).log(Level.SEVERE, null, ex);
        //}
        
           
   
    }
    
      /**
     * Convert bytes to hexadecimal string
     * @param bytes
     * @return 
     */
    public String bytesToHex(byte[] bytes) {

        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private byte[] concatenateArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    /**
     * Send APDU command to the card
     */
    public byte[] sendAPDU(byte[] data){

        


    baCommandAPDU = data;

    System.out.println("APDU >>>: " + bytesToHex(baCommandAPDU));

    try {

        ResponseAPDU r = channel.transmit(new CommandAPDU(baCommandAPDU));

        baResponceAPDU = r.getBytes();
        byte[] SW = new byte[]{(byte) r.getSW1(), (byte) r.getSW2()};
        System.out.println("APDU <<<: " + bytesToHex(baResponceAPDU)+" SW ="+bytesToHex(SW) + ", byte array length: " + baResponceAPDU.length);
        if (Arrays.equals(SW,new byte[]{(byte) 0x90, (byte) 0x00})) {
            counter++;
            System.out.println("counter:" + counter);
        }
        return r.getData();
        
        } catch (CardException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

    }
    
       
    /**
     * Create APDU command
     *
     * @param CLA
     * @param INS
     * @param P1
     * @param P2
     * @param Lc
     * @param data
     * @param Le
     * @return
     */
    public byte[] createAPDUComm(byte CLA, byte INS, byte P1, byte P2, int Lc, byte[] data, byte Le) {

        byte[] apduComm;
        int LcSize = 1;
        int LeSize = 1;

        if (Lc > 255) {
            LcSize = 3;
        }

        if (Lc > 255) {
            LeSize = 3;
        }

        if (Le == 0 && Lc == 0) {                                         //Case 1
            apduComm = new byte[4];
        } else if (Le != 0 && Lc == 0) {                                   //Case 2
            apduComm = new byte[5];
            apduComm[apduComm.length - 1] = Le;

        } else if (Le == 0 && Lc != 0) //Case 3
        {
            apduComm = new byte[4 + LcSize + data.length];
        } else if (Le != 0 && Lc != 0) {                                   //Case 4
            apduComm = new byte[4 + LcSize + data.length + LeSize];
            apduComm[apduComm.length - 1] = Le;
        } else {
            return null;
        }

        apduComm[0] = CLA;
        apduComm[1] = INS;
        apduComm[2] = P1;
        apduComm[3] = P2;

        if (Lc != 0) {
            apduComm[4] = (byte) data.length;
            System.arraycopy(data, 0, apduComm, 5, data.length);
        }

        return apduComm;
    }
    
    /**
     * Convertation Big Integer number to byte array without first byte specified significance
     * @param bigInt
     * @return 
     */
    public static byte[] bigIntToByteArray(BigInteger bigInt){
        
        byte[] directArray = bigInt.toByteArray();
        byte[] bigIntArray = new byte[directArray.length-1];
        
        System.arraycopy(directArray, 1, bigIntArray, 0, bigIntArray.length);
        return bigIntArray;
    }

    public byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    public byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }

    public static byte[] hexToByteArray(String hexString) {
        int len = hexString.length();
        byte[] byteArray = new byte[(len + 1) / 2];

        for (int i = 0; i < len; i += 2) {
            // Get the high and low nibbles of the current hex digit
            char highNibble = hexString.charAt(i);
            char lowNibble = (i + 1 < len) ? hexString.charAt(i + 1) : '0';

            int high = Character.digit(highNibble, 16);
            int low = Character.digit(lowNibble, 16);

            // Combine the nibbles into a single byte
            byte b = (byte) ((high << 4) | low);

            // Account for signed bytes in Java
            if (b > 127) {
                byteArray[i / 2] = (byte) (b - 256);
            } else {
                byteArray[i / 2] = b;
            }
        }

        return byteArray;
    }


    public static BigInteger byteArrayToBigInt(byte[] array){
        
        byte[] directArray = new byte[array.length+1];
        
        System.arraycopy(array, 0, directArray, 1, array.length);
        directArray[0] = (byte) 0x00;
            
        return new BigInteger(directArray);
    }
    
    
        public String bytesToHexPrint(byte[] bytes) {

        int i = -2;
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 4];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
            
            System.out.print("0x"+hexChars[j * 2]+hexChars[j * 2 + 1]+", ");
        } 
        System.out.println("");
        return new String(hexChars);
    }
    
}
