package helloworldjavacard;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CryptoCore{
    ObuParameters obuParameters;
    Cryptogram userCryptogram;
    Cryptogram receiverCryptogram;

    public CryptoCore(ObuParameters obuParameters, Cryptogram userCryptogram, Cryptogram receiverCryptogtam) {
        this.obuParameters = obuParameters;
        this.userCryptogram = userCryptogram;
        this.receiverCryptogram = receiverCryptogtam;
    }

    /*public String getCiphertext() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String hashType = "SHA-1";
        if (obuParameters.getKeyLengths() == 128){
            hashType = "SHA-1";
        } else if (obuParameters.getKeyLengths() == 192) {
            hashType = "SHA-224";
        }
        else if (obuParameters.getKeyLengths() == 256) {
            hashType = "SHA-256";
        }
        String userKey = hash(obuParameters.getDriverKey() + userCryptogram.getHatu(), hashType); //TODO: zkr8tit NA 128 BIT
        userKey= userKey.substring(0, (obuParameters.getKeyLengths()/8));
        String ukeyContent = userKey + "user" + userCryptogram.getNonce() + receiverCryptogram.getNonce();
        System.out.println("ukeycontent: " + ukeyContent);
        String ukeyString = hash(userKey + "user" + userCryptogram.getNonce() + receiverCryptogram.getNonce(),hashType);
        ukeyString = ukeyString.substring(0,(obuParameters.getKeyLengths()/8));
        String plainTextString = userCryptogram.getHatu() + obuParameters.getIdr() + userCryptogram.getNonce() + receiverCryptogram.getNonce();
        //System.out.println(ukeyContent + " " + plainTextString);
        byte[] plainText = plainTextString.getBytes();
        //System.out.println("plaintext"+Arrays.toString(plainText));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // pořešit padding
        SecretKey ukey = new SecretKeySpec(ukeyString.getBytes(),"AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, userCryptogram.getIv());
        cipher.init(Cipher.ENCRYPT_MODE, ukey, parameterSpec);
        byte[] cipherText = cipher.doFinal(plainText);
        String cipherTextHex = encodeHexString(cipherText);
        //cipherText = convertToPositiveBytes(cipherText);
        //System.out.println("vypocitane"+Arrays.toString(cipherText));
        System.out.println("vypocitane "+cipherTextHex);
        return cipherTextHex;
    }

    public String c3andC4(String ciphertextHex) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        //ciphertextHex = ciphertextHex.substring(0,96);
        byte[] ciphertext = decodeHexString(ciphertextHex);
        System.out.println("c2 byte array: "+Arrays.toString(ciphertext));
        //ciphertext = Arrays.copyOfRange(ciphertext,userCryptogram.getIv().length,ciphertextHex.length());
        String hashType = "SHA-1";
        if (obuParameters.getKeyLengths() == 128){
            hashType = "SHA-1";
        } else if (obuParameters.getKeyLengths() == 192) {
            hashType = "SHA-224";
        }else if (obuParameters.getKeyLengths() == 256) {
            hashType = "SHA-256";
        }
        String userKey = hash(obuParameters.getDriverKey() + userCryptogram.getHatu(), hashType);
        userKey= userKey.substring(0, (obuParameters.getKeyLengths()/8));
        String ukeyString = hash(userKey + "user" + userCryptogram.getNonce() + receiverCryptogram.getNonce(),hashType);
        ukeyString = ukeyString.substring(0,(obuParameters.getKeyLengths()/8));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey ukey = new SecretKeySpec(ukeyString.getBytes(),"AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, userCryptogram.getIv());
        cipher.init(Cipher.DECRYPT_MODE,ukey, parameterSpec);
        System.out.println("IV:" + Arrays.toString(userCryptogram.getIv()));
        System.out.println("key:" + Arrays.toString(ukey.getEncoded()));
        byte[] decryptedMessage = cipher.doFinal(ciphertext);
        byte[] ATU = Arrays.copyOfRange(decryptedMessage,0,32);
        String message = new String(Arrays.copyOfRange(decryptedMessage,32,decryptedMessage.length));
        //String message = "unlock";
        System.out.println("Message: " + message);
        if (obuParameters.getKeyLengths() == 128){
            hashType = "SHA-256";
        } else if (obuParameters.getKeyLengths() == 192) {
            hashType = "SHA-384";
        }else if (obuParameters.getKeyLengths() == 256) {
            hashType = "SHA-512";
        }
        String newHatu = hash(new String(ATU),hashType);
        newHatu = newHatu.substring(0,(obuParameters.getKeyLengths()/4));
        if(newHatu.equals(userCryptogram.getHatu())){
            System.out.println("ATU akceptovano");
            return "true";
        }
        else System.out.println("ATU neakceptovano");
        return "false";
    }*/

    //pro NFC
    public boolean dec(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException{
        //byte[] ciphertext = decodeHexString(ciphertextHex);
        System.out.println("c1 byte array: "+Arrays.toString(ciphertext));
        //ciphertext = Arrays.copyOfRange(ciphertext,userCryptogram.getIv().length,ciphertextHex.length());
        String hashType = "SHA-1";
        if (obuParameters.getKeyLengths() == 128){
            hashType = "SHA-1";
        } else if (obuParameters.getKeyLengths() == 192) {
            hashType = "SHA-224";
        }else if (obuParameters.getKeyLengths() == 256) {
            hashType = "SHA-256";
        }
        String userKey = hash(obuParameters.getDriverKey() + userCryptogram.getHatu(), hashType);
        userKey= userKey.substring(0, (obuParameters.getKeyLengths()/8));
        String ukeyString = hash(userKey + "user" + userCryptogram.getNonce() + receiverCryptogram.getNonce(),hashType);
        ukeyString = ukeyString.substring(0,(obuParameters.getKeyLengths()/8));
        System.out.println("ukeyString content: " + userKey + "user" + userCryptogram.getNonce() + receiverCryptogram.getNonce());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey ukey = new SecretKeySpec(ukeyString.getBytes(),"AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, userCryptogram.getIv());
        cipher.init(Cipher.DECRYPT_MODE,ukey, parameterSpec);
        System.out.println("IV:" + Arrays.toString(userCryptogram.getIv()));
        System.out.println("key:" + Arrays.toString(ukey.getEncoded()));
        byte[] decryptedMessage = cipher.doFinal(ciphertext);
        byte[] ATU = Arrays.copyOfRange(decryptedMessage,0,32);
        String message = new String(Arrays.copyOfRange(decryptedMessage,32,decryptedMessage.length));
        //String message = "unlock";
        System.out.println("Message: " + message);
        if (obuParameters.getKeyLengths() == 128){
            hashType = "SHA-256";
        } else if (obuParameters.getKeyLengths() == 192) {
            hashType = "SHA-384";
        }else if (obuParameters.getKeyLengths() == 256) {
            hashType = "SHA-512";
        }
        String newHatu = hash(new String(ATU),hashType);
        newHatu = newHatu.substring(0,(obuParameters.getKeyLengths()/4));
        if(newHatu.equals(userCryptogram.getHatu())){
            System.out.println("ATU akceptovano");
            return true;
        }
        else System.out.println("ATU neakceptovano");
        return false;
    }

    public boolean dec(String ciphertextHex) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException{
        byte[] ciphertext = decodeHexString(ciphertextHex);
        System.out.println("c1 byte array: "+Arrays.toString(ciphertext));
        //ciphertext = Arrays.copyOfRange(ciphertext,userCryptogram.getIv().length,ciphertextHex.length());
        String hashType = "SHA-1";
        if (obuParameters.getKeyLengths() == 128){
            hashType = "SHA-1";
        } else if (obuParameters.getKeyLengths() == 192) {
            hashType = "SHA-224";
        }else if (obuParameters.getKeyLengths() == 256) {
            hashType = "SHA-256";
        }
        String userKey = hash(obuParameters.getDriverKey() + userCryptogram.getHatu(), hashType);
        userKey= userKey.substring(0, (obuParameters.getKeyLengths()/8));
        String ukeyString = hash(userKey + "user" + userCryptogram.getNonce() + receiverCryptogram.getNonce(),hashType);
        ukeyString = ukeyString.substring(0,(obuParameters.getKeyLengths()/8));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey ukey = new SecretKeySpec(ukeyString.getBytes(),"AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, userCryptogram.getIv());
        cipher.init(Cipher.DECRYPT_MODE,ukey, parameterSpec);
        System.out.println("IV:" + Arrays.toString(userCryptogram.getIv()));
        System.out.println("key:" + Arrays.toString(ukey.getEncoded()));
        byte[] decryptedMessage = cipher.doFinal(ciphertext);
        byte[] ATU = Arrays.copyOfRange(decryptedMessage,0,32);
        String message = new String(Arrays.copyOfRange(decryptedMessage,32,decryptedMessage.length));
        //String message = "unlock";
        System.out.println("Message: " + message);
        if (obuParameters.getKeyLengths() == 128){
            hashType = "SHA-256";
        } else if (obuParameters.getKeyLengths() == 192) {
            hashType = "SHA-384";
        }else if (obuParameters.getKeyLengths() == 256) {
            hashType = "SHA-512";
        }
        String newHatu = hash(new String(ATU),hashType);
        newHatu = newHatu.substring(0,(obuParameters.getKeyLengths()/4));
        if(newHatu.equals(userCryptogram.getHatu())){
            System.out.println("ATU akceptovano");
            return true;
        }
        else System.out.println("ATU neakceptovano");
        return false;
    }

    public static String hash(String input, String hashType)
    {
        try {
            // getInstance() method is called with algorithm SHA-1
            MessageDigest md = MessageDigest.getInstance(hashType);

            // digest() method is called
            // to calculate message digest of the input string
            // returned as array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);

            // Add preceding 0s to make it 32 bit
            /*while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }*///

            // return the HashText
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] convertToPositiveBytes(byte[] bytes){
        byte[] byteArray = new byte[bytes.length];
        for(int i=0;i<bytes.length;i++){
            byteArray[i] = byteAbs(bytes[i]);
        }
        return byteArray;
    }

    byte byteAbs(byte b) {
        return b >= 0? b : (byte) (b == -128 ? 127 : -b);
    }

    public String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    public String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
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

}
