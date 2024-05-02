import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class pruebaSimetrica {

    private BigInteger p;
    private int g;
    private int gx1;
    private int gx2;
    private int x1;
    private int x2;

    public pruebaSimetrica(){
        this.p = procesarP();
        this.g = 2;
        this.gx1 = procesarGX1();
        this.gx2 = procesarGX2();
    }

    public BigInteger procesarP(){

        String hexString = "aebe47eda048868ec8a8db163a08c196adeddd700dabab34d30f96892057200fc60a5a26b2aa86c302054f6786cc11ac7b240429f9480bf53bb149bf6fa3b35667c30c9917b679061e80ab44dc688ba111736e94b68f6b24f30cecb94700ae62679745e03c1408af50a7628066ca547e2c9150758464dfae535543cae4ac97ef";

        BigInteger bigInt = new BigInteger(hexString, 16);
        return bigInt;
    }

    public int procesarGX1(){
        Random random = new Random();
        int x = random.nextInt(10) + 1;
        int resultado = (int) Math.pow(g,x);
        this.x1 = x;
        return resultado;
    }

    public int procesarGX2(){
        Random random = new Random();
        int x = random.nextInt(10) + 1;
        int resultado = (int) Math.pow(g,x);
        this.x2 = x;
        return resultado;
    }

    public void generarVectorInicial(){

        System.out.println("Generar vector");

    }


    public byte[] cifrarSimetrico(String message, byte[] key)throws Exception{

        // Generate random IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        // Create AES cipher in CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Encrypt the message
        byte[] encrypted = cipher.doFinal(message.getBytes());

        // Concatenate IV and encrypted message
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

        return result;
    }

    public static String decryptAES(byte[] encrypted, byte[] key) throws Exception {
        // Extract IV from the encrypted message
        byte[] iv = Arrays.copyOfRange(encrypted, 0, 16);
        byte[] encryptedMessage = Arrays.copyOfRange(encrypted, 16, encrypted.length);

        // Create AES cipher in CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Decrypt the message
        byte[] decrypted = cipher.doFinal(encryptedMessage);

        return new String(decrypted);
    }


    public void generarLlaves() throws Exception{

        //CALCULAR Y
        BigInteger y1 = BigInteger.valueOf(gx1).modPow(BigInteger.valueOf(g), p);
        System.out.println("y1: " + y1);

        BigInteger y2 = BigInteger.valueOf(gx2).modPow(BigInteger.valueOf(g), p);
        System.out.println("y2: " + y2);

        //Calular Z LLAVE MAESTRA (Debe dar igual en ambos casos)
        BigInteger z1 = y2.modPow(BigInteger.valueOf(x1), p);
        System.out.println("z1: " + z1);
        BigInteger z2 = y1.modPow(BigInteger.valueOf(x2), p);
        System.out.println("z1: " + z2);


        //Realizar digest con SHA-512
        
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(z1.toString().getBytes());
        byte[] hash = digest.digest();

        byte[] llaveAutentica = Arrays.copyOfRange(hash, 0, hash.length / 2);
        byte[] llaveHMAC = Arrays.copyOfRange(hash, hash.length / 2, hash.length);

        String message = "HOLA MUNDI";

        // Encrypt the message using AES in CBC mode with PKCS5Padding
        byte[] encrypted = cifrarSimetrico(message, llaveAutentica);

        // Print the encrypted message
        System.out.println("Encrypted message (hex): " + byteArrayToHexString(encrypted));

        String decrypted = decryptAES(encrypted, llaveAutentica);

        // Print the decrypted message
        System.out.println("Decrypted message: " + decrypted);

        
    }

    public static String byteArrayToHexString(byte[] array) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : array) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) throws Exception {
        
        System.out.println("Estoy corriendo");

        pruebaSimetrica prueba = new pruebaSimetrica();
        prueba.generarLlaves();
    }


    
}
