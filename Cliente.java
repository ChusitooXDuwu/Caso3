import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;

public class Cliente {

    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private PublicKey publicKey;
    private BigInteger p;
    private int g;
    private int gx1;
    private int gx2;
    private int x2;
    private byte[] vi;
    private byte[] llaveAutentica;
    private byte[] llaveHMAC;


    public Cliente() throws InvalidKeySpecException, NoSuchAlgorithmException{

        this.publicKey = procesarLlavePublica();

    }


    public PublicKey procesarLlavePublica() throws InvalidKeySpecException, NoSuchAlgorithmException{

        byte[] publicKeyBytes = Base64.getDecoder().decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCoEIYKeWDBjpm47lq2nemgYvJipMCfJgQ1dt89sqt6owq8vURbhQV6U+F6+ZuAdmvvxHtBCk1NwrU+q+g+WwDpn/pR1couaJHBU4+/c8n6sRJ/ewu22/vlpPgI8lqZduVCogZzuiJp77k040zsq6QGqfUshhIVLZIc1z0yxUMlwIDAQAB");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        PublicKey publi = publicKeyFactory.generatePublic(publicKeySpec);

        return publi;

    }


    public byte[] decifrarPublica(PublicKey publicKey, byte[] msg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

        Cipher cifrador = Cipher.getInstance("RSA");
        cifrador.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] textoClaro = cifrador.doFinal(msg);

        return textoClaro;

    }

    public void startConnection(String ip, int port) throws UnknownHostException, IOException {
        clientSocket = new Socket(ip, port);
        out = new PrintWriter(clientSocket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
    }

    public int procesarGX(){
        Random random = new Random();
        int x = random.nextInt(10) + 1;
        int resultado = (int) Math.pow(g,x);
        this.x2 = x;
        return resultado;
    }


    public void procesarLlaves() throws Exception{

        //Calcular y1
        BigInteger y1 = BigInteger.valueOf(gx1).modPow(BigInteger.valueOf(g), p);

        //Calcular z2
        BigInteger z2 = y1.modPow(BigInteger.valueOf(x2), p);
        
        //Realizar digest con SHA-512
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(z2.toString().getBytes());
        byte[] hash = digest.digest();

        llaveAutentica = Arrays.copyOfRange(hash, 0, hash.length / 2);
        llaveHMAC = Arrays.copyOfRange(hash, hash.length / 2, hash.length);
    }


    public byte[] cifrarSimetrico(String message, byte[] key)throws Exception{

        // Create AES cipher in CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(vi));

        // Encrypt the message
        byte[] encrypted = cipher.doFinal(message.getBytes());

        return encrypted;
    }


    public void secureStart() throws Exception {

        //Enviar inicializacion del servidor con el reto
        String segstart =  "SECURE INIT" + "," + "Reto";;
        out.println(segstart);

        //Recibir el reto cifrado y decifrarlo con la llave publica
        String resp = in.readLine();
        byte[] byteArray = Base64.getDecoder().decode(resp);
        byte[] verif = decifrarPublica(publicKey, byteArray);
        String descifradoClaro = new String(verif, StandardCharsets.UTF_8);

        //Si el reto es correcto enviar OK
        if (descifradoClaro.equals("Reto")){

            out.println("OK");
        }


        //Recibir P, G y G^x
        p = new BigInteger(in.readLine());
        g =  Integer.parseInt(in.readLine());
        gx1 = Integer.parseInt(in.readLine());
        vi = Base64.getDecoder().decode(in.readLine());

        //RECIBIR VALORES CIFRADOS 
        //TODO: FALTA RECIBIR Y ENVIAR OK

        //Enviar gx2
        gx2 = procesarGX();
        out.println(gx2);

        //Procesar Llaves
        procesarLlaves();

        //Recibir CONTINUAR
        String cont = in.readLine();
        if (cont.equals("CONTINUAR")){
            System.out.println("CONTINUAR RECIBIDO");
        }

        //Enviar usuario
        byte[] loginCifrado = cifrarSimetrico("SOYUNUSUARIO", llaveAutentica);
        out.println(Base64.getEncoder().encodeToString(loginCifrado));

        //Enviar Contraseña
        byte[] passCifrado = cifrarSimetrico("SOYUNAPASS", llaveAutentica);
        out.println(Base64.getEncoder().encodeToString(passCifrado));



        
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

        Cliente cliente = new Cliente();
        cliente.startConnection("127.0.0.1", 6666);
        cliente.secureStart();

    }
}
