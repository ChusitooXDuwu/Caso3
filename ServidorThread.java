import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
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
    private byte[] llaveAutentica;
    private byte[] llaveHMAC;

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

        llaveAutentica = Arrays.copyOfRange(hash, 0, hash.length / 2);
        llaveHMAC = Arrays.copyOfRange(hash, hash.length / 2, hash.length);
    }

    public static String decifrarSimetrico(byte[] encrypted, byte[] key, byte[] iv) throws Exception {
        
        // Create AES cipher in CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Decrypt the message
        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted);
    }

    public boolean verificarUsuario(byte[] uCif, byte[] pCif) throws Exception{


        String usuario = decifrarSimetrico(uCif, llaveAutentica, vi);
        String pass = decifrarSimetrico(pCif, llaveAutentica, vi);

        System.out.println(usuario);
        System.out.println(pass);
        
        return true;

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
            String textoCifradoEnviar = Base64.getEncoder().encodeToString(primer);
            out.println(textoCifradoEnviar);
        }
        //Recibir del cliente OK o ERROR
        String oka = in.readLine();
        
        //Si el cliente verifico el reto se puede seguir
        if (oka.equals("OK")){
        
            System.out.println("Verificacion Terminada Exitosamente");
        }
        //Enviar valores de P, G, G^x y vector de inicializacion al cliente
        out.println(p);
        out.println(g);
        out.println(gx1);
        out.println(Base64.getEncoder().encodeToString(vi));

        //Enviar valores cifrados
        //TODO: FALTA HACER LA VERIFICACION

        //Recibir gx2
        gx2 = Integer.parseInt(in.readLine());

        //Calcular llaves
        procesarLlaves();

        //Enviar Continuar
        out.println("CONTINUAR");

        //Recibir Usuario
        byte[] usuarioCifrado = Base64.getDecoder().decode(in.readLine());

        //Recibir Contraseña
        byte[] passCifrado = Base64.getDecoder().decode(in.readLine());

        //Verificar usuario y contraseña
        boolean verif = verificarUsuario(usuarioCifrado, passCifrado);




        in.close();
        out.close();
        clientSocket.close();
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
