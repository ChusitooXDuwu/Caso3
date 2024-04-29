import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import java.io.*;

public class Cliente {

    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private PublicKey publicKey;


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

    public void secureStart() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

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
        String p = in.readLine();
        String g = in.readLine();
        String gx = in.readLine();

        System.out.println("\n\n");

        System.out.println(p);
        System.out.println("\n\n");
        System.out.println(g);
        System.out.println("\n\n");
        System.out.println(gx);
    }


    public static void main(String[] args) throws UnknownHostException, IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        Cliente cliente = new Cliente();
        cliente.startConnection("127.0.0.1", 6666);
        cliente.secureStart();

    }
}
