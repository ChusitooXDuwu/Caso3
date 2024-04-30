import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Random;

import javax.crypto.*;
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
    private int gx;

    //Constructor
    public ServidorThread(Socket clientSocket, PrivateKey privateKey, BigInteger p, int g){

        this.clientSocket = clientSocket;
        this.privateKey = privateKey;
        this.p = p;
        this.g = g;
        this.gx = procesarGX();

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
        return resultado;
    }

    public void start(){

        //Crear IN y OUT para la conexion
        try {
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
            out.println(gx);


            in.close();
            out.close();
            clientSocket.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        

        


    }


    @Override
    public void run(){

        //Crear IN y OUT para la conexion
        
        



        
        System.out.println("Nuevo servidor");

    }
    
}
