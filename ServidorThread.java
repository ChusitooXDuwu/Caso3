import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;

public class ServidorThread extends Thread{


    //Atributos para cada cliente
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private PrivateKey privateKey;
    private BigInteger p;
    private int g;
    private int x1;
    private int gx1;
    private int gx2;
    private byte[] vi;
    private SecretKeySpec llaveAutentica;
    private SecretKeySpec llaveHMAC;

    private long generarFirmaTime;
    private long decifrarConsultaTime;
    private long verificarCodigoAuthTime;

    //Constructor
    public ServidorThread(Socket clientSocket, PrivateKey privateKey, BigInteger p, int g){

        this.clientSocket = clientSocket;
        this.privateKey = privateKey;
        this.p = p;
        this.g = g;
        this.gx1 = procesarGX();
        this.vi = generarVi();

    }

    public byte[] generarVi(){
        Random random = new Random();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        return iv;
    }


    public byte[] cifrarPrivada(PrivateKey privateKey, String msg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

        Cipher cifrador = Cipher.getInstance("RSA");
        cifrador.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] textoCifrado = cifrador.doFinal(msg.getBytes(StandardCharsets.UTF_8));

        return textoCifrado;

    }

    public int procesarGX(){
        Random random = new Random();
        int x = random.nextInt(10) + 1;
        int resultado = (int) Math.pow(g,x);
        this.x1 = x;
        return resultado;
    }


    public void procesarLlaves() throws Exception{

        //Calcular y2
        BigInteger y2 = BigInteger.valueOf(gx2).modPow(BigInteger.valueOf(g), p);

        //Calular Z1
        BigInteger z1 = y2.modPow(BigInteger.valueOf(x1), p);
        
        //Realizar digest con SHA-512
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(z1.toString().getBytes());
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

    public boolean verificarUsuario(byte[] uCif, byte[] pCif) throws Exception{


        String usuario = decifrarSimetrico(uCif, llaveAutentica, vi);
        String pass = decifrarSimetrico(pCif, llaveAutentica, vi);

        if(usuario.equals("SOYUNUSUARIO") && pass.equals("SOYUNAPASS")){
            return true;
        }

        return false;

    }


    public byte[] signDocument(PrivateKey priv, String msg) throws Exception{

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(priv);

        byte[] data = msg.getBytes();

        signature.update(data);

        return signature.sign();


    }


    public byte[] calcularHMAC(SecretKeySpec secretKeySpec, String msg) throws NoSuchAlgorithmException, InvalidKeyException{

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);

        return  mac.doFinal(msg.getBytes());
    }


    public void printTimes(){

        System.out.println("\n----- Protocolo terminado ----- \n" + "- Tiempo para generar firma: " + generarFirmaTime + " nanosegundos\n" + "- Tiempo para decifrar consulta: " + decifrarConsultaTime + " nanosegundos\n" + "- Tiempo para verificar el codigo: " + verificarCodigoAuthTime + " nanosegundos");
    }

    public void handleCliente() throws Exception{

        //Crear IN y OUT para la conexion
        
        out = new PrintWriter(clientSocket.getOutputStream(),true);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));


        //Primer paso Recibir Reto
        String[] greeting = in.readLine().split(",");
        if(greeting[0].equals("SECURE INIT")){
            //Cifrar el reto con la llave privada y enviarlo al cliente
            byte[] primer = cifrarPrivada(privateKey, greeting[1]); 
            out.println(byteArrayToHexString(primer));
        }
        //Recibir del cliente OK o ERROR
        String oka = in.readLine();
        
        //Si el cliente verifico el reto se puede seguir
        if (oka.equals("OK")){
        
            System.out.println("Verificacion Terminada Exitosamente");
        }
        else{

            System.out.println("Verificacion Fallida");
            in.close();
            out.close();
            System.out.println("Sesion terminada");
            clientSocket.close();

        }
        //Enviar valores de P, G, G^x y vector de inicializacion al cliente
        out.println(g);
        out.println(p);
        out.println(gx1);
        out.println(byteArrayToHexString(vi));

        //Enviar valores cifrados firma
        String firma = g + "," + p + "," + gx1;

        long startTime = System.nanoTime();
        byte[] firmaCifrada = signDocument(privateKey, firma);
        long endTime = System.nanoTime();

        generarFirmaTime = endTime - startTime;

        out.println(byteArrayToHexString(firmaCifrada));

        //Recibir OK
        oka = in.readLine();
        if (oka.equals("OK")){
        
            System.out.println("Verificado G, P y G^X correctamente");
        }
        else{

            System.out.println("Error firma G, P y G^X correctamente");
            in.close();
            out.close();
            System.out.println("Sesion terminada");
            clientSocket.close();

        }

        //Recibir gx2
    
        gx2 = Integer.parseInt(in.readLine());
    

        //Calcular llaves
        procesarLlaves();

        //Enviar Continuar
        out.println("CONTINUAR");

        //Recibir Usuario
        byte[] usuarioCifrado = hexStringToByteArray(in.readLine());

        //Recibir Contraseña
        byte[] passCifrado = hexStringToByteArray(in.readLine());

        //Verificar usuario y contraseña
        boolean verif = verificarUsuario(usuarioCifrado, passCifrado);

        if(verif){
            System.out.println("Usuario Verificado");   
            out.println("OK");
        }else{
            System.out.println("Usuario No Verificado");
            out.println("ERROR");
            in.close();
            out.close();
            System.out.println("Sesion terminada");
            clientSocket.close();
            
            return;
        }

        //Recibir Consulta
        byte[] consultaCifrada = hexStringToByteArray(in.readLine());

        startTime = System.nanoTime();
        String consulta = decifrarSimetrico(consultaCifrada, llaveAutentica, vi);
        endTime = System.nanoTime();

        decifrarConsultaTime = endTime - startTime;

        byte[] hmacConsulta = hexStringToByteArray(in.readLine());


        startTime = System.nanoTime();
        if(Arrays.equals(hmacConsulta, calcularHMAC(llaveHMAC, consulta))){

            System.out.println("Consulta verificado Correctamente");

        }else{
            System.out.println("El consulta no tiene el mismo codigo");
        }
        endTime = System.nanoTime();

        verificarCodigoAuthTime = endTime - startTime;


        //Enviar Respuesta
        String respuesta = "1";
        byte[] respuestaCifrada = cifrarSimetrico(respuesta, llaveAutentica);
        out.println(byteArrayToHexString(respuestaCifrada));

        //Enviar HMAC respuesta
        byte[] hmacRespuesta = calcularHMAC(llaveHMAC, respuesta);
        out.println(byteArrayToHexString(hmacRespuesta));

        in.close();
        out.close();
        clientSocket.close();

        System.out.println("Sesion terminada");
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
        System.out.println("Nuevo servidor");
        try {
            handleCliente();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    
}
