import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class GenerarLlavesAsimetricas {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {

        System.out.println("\n\n***** GENERADOR DE LLAVES ASIMETRICAS *****");

        // Generate key pair
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Export public key
        byte[] publicKeyBytes = publicKey.getEncoded();
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
        System.out.println("\n ----- Public key: ----- \n");
        System.out.println(publicKeyBase64);
        System.out.println("\n");
        System.out.println(publicKey);

        // Export private key
        byte[] privateKeyBytes = privateKey.getEncoded();
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeyBytes);
        System.out.println("\n ----- Private key: ----- \n");
        System.out.println(privateKeyBase64);
        System.out.println("\n");
        System.out.println(privateKey);

    }
}
