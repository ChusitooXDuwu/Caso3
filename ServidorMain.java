import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;

public class ServidorMain {


    //Atributos
    private ServerSocket serverSocket;
    private PrivateKey privateKey;
    private BigInteger p;
    private int g;



    //Constructor
    public ServidorMain() throws InvalidKeySpecException, NoSuchAlgorithmException {

        this.privateKey = procesarLlavePrivada();
        this.p = procesarP();
        this.g = 2;
    }


    //Procesar los valores de p 
    public BigInteger procesarP(){

        String hexString = "aebe47eda048868ec8a8db163a08c196adeddd700dabab34d30f96892057200fc60a5a26b2aa86c302054f6786cc11ac7b240429f9480bf53bb149bf6fa3b35667c30c9917b679061e80ab44dc688ba111736e94b68f6b24f30cecb94700ae62679745e03c1408af50a7628066ca547e2c9150758464dfae535543cae4ac97ef";

        BigInteger bigInt = new BigInteger(hexString, 16);
        return bigInt;
    }


    //Procesar la llave privada de un String a la llave
    public PrivateKey procesarLlavePrivada() throws InvalidKeySpecException, NoSuchAlgorithmException{

        byte[] privateKeyBytes = Base64.getDecoder().decode("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIKgQhgp5YMGOmbjuWrad6aBi8mKkwJ8mBDV23z2yq3qjCry9RFuFBXpT4Xr5m4B2a+/Ee0EKTU3CtT6r6D5bAOmf+lHVyi5okcFTj79zyfqxEn97C7bb++Wk+AjyWpl25UKiBnO6ImnvuTTjTOyrpAap9SyGEhUtkhzXPTLFQyXAgMBAAECgYALs2xIOtSGwJORrNtqkWg/X4JUitexVNTQST/QeVDddFGa9Ulzhr9A2TXY4rEw8HR99CkYaJOCY0xSmKQL0NvWdHnUtTfBh7urxn2zXkjg26LUICmS8tcRWKr22mCrWatGDsov5hxihb4BgLLI2LohCfwHBApPXxdktQLi+UcyeQJBAN6TVcwsvNXRGJmWFiujP5NzSasnuWX2YPggy5/NvK8txFuFnz6llN3H99E00iFrXK9jKw6AE6Oudq3Z3MfcTL8CQQCWPgcPyGx6peDbbAa4Y3UxoY4uGzY7MTQZvLuguEA4pZXPa+R+79VzfSl2arddi2z5+NmxJHPcoHpBM6QS6b4pAkBKom0qwfWwXSU6mzFkAKHY99fEJNXucuehTJ37QCn9NAOcDPqRL0Tz+ZIH/QZZXn798OsHObtcL6xsL5nxCtZRAkARw7HIDvWsptJof2RoBvKDdMu/7d3Cr/WuGV/CCCcny4RkKyiwTaFab3EonEOkHuk6wU7UIDBG5P6vmPCMf/DJAkEAk0AT/W5qRV2L1zwnyOp1KZVFkw7dgICOldTExs1J9z/sbS39VqoADq5+6FmixFOKwgLXhl3LKj4Bv3A1IGf06A==");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        PrivateKey priv = privateKeyFactory.generatePrivate(privateKeySpec);

        return priv;
    }


    public void start1(int port) throws IOException{

        serverSocket = new ServerSocket(port);

        System.out.println("Inicializado el servidor en el puerto " + port);

        while(true){
            Socket clienSocket = serverSocket.accept();
            System.out.println("New client connected: " + clienSocket);
            
            ServidorThread cliente = new ServidorThread(clienSocket, privateKey, p, g);
            cliente.start();
        }

    }

    public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        //Iniciar el servidor
        ServidorMain server = new ServidorMain();
        server.start1(6666);
        
    }
}
