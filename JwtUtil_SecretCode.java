package africa.finserve.jengaadminapisv3.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class JwtUtil_SecretCode {
//    private static final String PRIVATE_KEY_PATH = "/path/to/private_key.pem";
//    private static final String PUBLIC_KEY_PATH = "/path/to/public_key.pem";

    static String PUBLIC_KEY_PATH = "v3-305-keys/public_key.der";

    // static String PubKey =
    // "/srv/applications/EAP-6.4.0/externalConfigs/certs/publickey.pem";

    static String PRIVATE_KEY_PATH = "v3-305-keys/private_key.der";
    private static final long EXPIRATION_TIME = 86400000; // 24 hours

    public static String generateToken(String username) {
        try {
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_PATH));
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_PATH));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + EXPIRATION_TIME);

            return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(now)
                    .setExpiration(expiryDate)
                    .signWith(SignatureAlgorithm.RS256, privateKey)
                    .compact();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static boolean validateToken(String token) {
        try {
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_PATH));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}

