import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;

public class Cliente extends Thread{

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

    private long verificarFirmaTime;
    private long calcularGX2Time;
    private long cifrarConsultaTime;
    private long generarCodigoAuthTime;



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

    public void cerrarConexion() throws Exception {
        in.close();
        out.close();
        clientSocket.close();
    }

    public void validarRespuesta(String respuesta) throws Exception {
        if (!respuesta.equals("Valid")) {
            throw new Exception("Respuesta inválida");
        }

    }



    public void printTimes(){

        System.out.println("\n\n----- Protocolo terminado -----\n" + "- Tiempo para verificar la firma: " + verificarFirmaTime + " nanosegundos\n" + "- Tiempo para calcular G^y: " + calcularGX2Time + " nanosegundos\n" + "- Tiempo para cifrar consulta: " + cifrarConsultaTime + " nanosegundos\n" + "- Tiempo para cifrar consulta: " + cifrarConsultaTime + " nanosegundos\n" + "- Tiempo para generar codigo de autenticacion: " + generarCodigoAuthTime + " nanosegundos\n");
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
        }else{

            out.println("ERROR");
            in.close();
            out.close();
            System.out.println("Error en el reto");
            interrupt();
            return;
        }

        //Recibir P, G y G^x
        g =  Integer.parseInt(in.readLine());
        p = new BigInteger(in.readLine());
        gx1 = Integer.parseInt(in.readLine());
        vi = hexStringToByteArray(in.readLine());

        //RECIBIR VALORES CIFRADOS 
        // lave para probar el error
        //String firma = "1bb865fb3ec7deb10845c9ad0765212b168d8d75b422e1f3eff2a228699e77d6dd5c5ff9c1620b014557de60acbd140552cdf53bcc5b11b7288b191fa665bb577ed51f72c550fa430939a60295f3fc924c533420a93cbd51f7ecab75d631dc9448ff9abf99b7c12e6154b8e577aecd4ce15bc4859f75a0521eee9c1e59a8d0e3";
        String firma = in.readLine();
        byte[] firmaBytes = hexStringToByteArray(firma);
        
        String aVerificar = g + "," + p + "," + gx1;

        long startTime = System.nanoTime();
        boolean verificar = verificarFirma(publicKey, aVerificar, firmaBytes);
        long endTime = System.nanoTime();

        verificarFirmaTime = endTime - startTime;


        if(verificar){
            out.println("OK");
        }
        else{
            out.println("ERROR");
            //close connection
            in.close();
            out.close();
            interrupt();
            return;

        }


        //Enviar gx2S
        startTime = System.nanoTime();
        gx2 = procesarGX();
        endTime = System.nanoTime();

        calcularGX2Time = endTime - startTime;

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
        }else{
            System.out.println("Error verificando usuario");
            in.close();
            out.close();
            interrupt();
            return;

        }


        //Enviar Consulta
        String consulta = "HOLA ME PueDES HACER ESTO SOY UNA CONSULTA";

        startTime = System.nanoTime();
        byte[] consultaCifrada = cifrarSimetrico(consulta, llaveAutentica);
        endTime = System.nanoTime();

        cifrarConsultaTime =  endTime - startTime;
        out.println(byteArrayToHexString(consultaCifrada));

        //Enviar HMAC Consulta
        startTime = System.nanoTime();
        byte[] hmacConsulta = calcularHMAC(llaveHMAC, consulta);
        endTime = System.nanoTime();

        generarCodigoAuthTime = endTime - startTime;

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

        printTimes();

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

    @Override
    public void run(){

        try {
            startConnection("127.0.0.1", 6666);
            secureStart();
        } catch (Exception e) {

            e.printStackTrace();
        }
        
    }


    public static void main(String[] args) throws Exception {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("\n\n *** Cuantos clientes quiere: ");
            int numClientes = Integer.parseInt(scanner.nextLine());

            Cliente[] clientes = new Cliente[numClientes];
            for (int i = 0; i < numClientes; i++) {
                clientes[i] = new Cliente();
                
                clientes[i].start();
            }
        }
        catch (Exception e) {
            System.out.println("Error de conexión: " + e.getMessage());
        }

    }
}
