import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;

public class Cliente implements Runnable {

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
    private SecretKeySpec llaveAutentica;
    private SecretKeySpec llaveHMAC;


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

        llaveAutentica = new SecretKeySpec(Arrays.copyOfRange(hash, 0, hash.length / 2), "AES");
        llaveHMAC = new SecretKeySpec(Arrays.copyOfRange(hash, hash.length / 2, hash.length), "HmacSHA256");
    }


    public static String decifrarSimetrico(byte[] encrypted, SecretKeySpec secretKey, byte[] iv) throws Exception {
        
        // Create AES cipher in CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Decrypt the message
        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted);
    }

    public byte[] cifrarSimetrico(String message, SecretKeySpec secretKey)throws Exception{

        // Create AES cipher in CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(vi));

        // Encrypt the message
        byte[] encrypted = cipher.doFinal(message.getBytes());

        return encrypted;
    }


    public boolean verificarFirma(PublicKey pub, String data, byte[] signatureBytes) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException{

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pub);
        verifier.update(data.getBytes());

        return verifier.verify(signatureBytes);

    }


    public byte[] calcularHMAC(SecretKeySpec secretKeySpec, String msg) throws NoSuchAlgorithmException, InvalidKeyException{

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);

        return  mac.doFinal(msg.getBytes());
    }



    public void secureStart() throws Exception {

        //Enviar inicializacion del servidor con el reto
        String segstart =  "SECURE INIT" + "," + "Reto";;
        out.println(segstart);

        //Recibir el reto cifrado y decifrarlo con la llave publica
        String resp = in.readLine();
        byte[] verif = decifrarPublica(publicKey, hexStringToByteArray(resp));
        String descifradoClaro = new String(verif, StandardCharsets.UTF_8);

        //Si el reto es correcto enviar OK
        if (descifradoClaro.equals("Reto")){

            out.println("OK");
        }


        //Recibir P, G y G^x
        g =  Integer.parseInt(in.readLine());
        p = new BigInteger(in.readLine());
        gx1 = Integer.parseInt(in.readLine());
        vi = hexStringToByteArray(in.readLine());

        //RECIBIR VALORES CIFRADOS 
        String firma = in.readLine();
        byte[] firmaBytes = hexStringToByteArray(firma);
        
        String aVerificar = g + "," + p + "," + gx1;


        boolean verificar = verificarFirma(publicKey, aVerificar, firmaBytes);

        if(verificar){
            out.println("OK");
        }




        //Enviar gx2S
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
        out.println(byteArrayToHexString(loginCifrado));

        //Enviar Contraseña
        byte[] passCifrado = cifrarSimetrico("SOYUNAPASS", llaveAutentica);
        out.println(byteArrayToHexString(passCifrado));


        //Recibir OK
        String oka = in.readLine();
        if (oka.equals("OK")){
    
            System.out.println("Ya puedo enviar la consulta");
        }


        //Enviar Consulta
        String consulta = "HOLA ME PueDES HACER ESTO SOY UNA CONSULTA";
        byte[] consultaCifrada = cifrarSimetrico(consulta, llaveAutentica);
        out.println(byteArrayToHexString(consultaCifrada));

        //Enviar HMAC Consulta
        byte[] hmacConsulta = calcularHMAC(llaveHMAC, consulta);
        out.println(byteArrayToHexString(hmacConsulta));

        //Recibir Respuesta
        byte[] respuestaCifrada = hexStringToByteArray(in.readLine());
        String respuesta = decifrarSimetrico(respuestaCifrada, llaveAutentica, vi);

        //Recibir HMAC Respuesta
        byte[] hmacRespuesta = hexStringToByteArray(in.readLine());

        //Verificar mensaje
        if(Arrays.equals(hmacRespuesta, calcularHMAC(llaveHMAC, respuesta))){

            System.out.println("Respuesta verificado Correctamente");

        }else{
            System.out.println("La Respuesta no tiene el mismo codigo");
        }


        
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

    public static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                 + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }

    public void measureTimes(int numClients) throws Exception {
        for (int i = 0; i < numClients; i++) {
            long startTime, endTime, duration;

            // Verify the signature
            startTime = System.nanoTime();
            // Logic to verify the signature
            endTime = System.nanoTime();
            duration = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);
            System.out.println("Time to verify the signature for client " + i + ": " + duration + " ms");

            // Calculate Gy
            startTime = System.nanoTime();
            // Logic to calculate Gy
            endTime = System.nanoTime();
            duration = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);
            System.out.println("Time to calculate Gy for client " + i + ": " + duration + " ms");

            // Encrypt the query
            startTime = System.nanoTime();
            endTime = System.nanoTime();
            duration = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);
            System.out.println("Time to encrypt the query for client " + i + ": " + duration + " ms");

            // Generate the authentication code
            startTime = System.nanoTime();

            endTime = System.nanoTime();
            duration = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);
            System.out.println("Time to generate the authentication code for client " + i + ": " + duration + " ms");

            // Wait for a while before moving to the next client
            Thread.sleep(1000);
        }
    }

    @Override
    public void run() {
        try {
            secureStart();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        Cliente cliente = new Cliente();
        cliente.startConnection("127.0.0.1", 6666);
        cliente.measureTimes(4); // Adjust the numClients according to the tests
        cliente.secureStart();

    }
}
