package com.seguriry.demo.Jwt;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


//que es un servicio de Spring encargado de generar, validar y obtener
// información de tokens JWT

@Service
public class JwtService {
    //Es una clave secreta utilizada para firmar y verificar los tokens JWT.
    private static final String SECRET_KEY="586E3272357538782F413F4428472B4B6250655368566B597033733676397924";

    //getToken(UserDetails user): Genera un token JWT para un usuario proporcionado como UserDetails.
    // Invoca al método privado getToken(Map<String, Object> extraClaims, UserDetails user) con un
    // mapa vacío para reclamaciones adicionales (extraClaims).
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    //getToken(Map<String, Object> extraClaims, UserDetails user): Genera un token JWT para un
    // usuario con reclamaciones adicionales (extraClaims). Define las reclamaciones del token,
    // como el nombre de usuario (subject), la fecha de emisión (issuedAt) y la fecha de expiración
    // (expiration), y luego firma el token utilizando el algoritmo HS256 y la clave secreta (getKey()).

    private String getToken(Map<String,Object> extraClaims, UserDetails user) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //getKey(): Devuelve una instancia de Key que representa la clave secreta utilizada para firmar
    // y verificar los tokens JWT. La clave se obtiene a partir de la cadena SECRET_KEY, que es
    // convertida desde una representación hexadecimal a bytes y luego se convierte en una clave
    // HMAC utilizando Keys.hmacShaKeyFor(keyBytes)
    private Key getKey() {
        byte[] keyBytes=Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //getUsernameFromToken(String token): Obtiene el nombre de usuario (subject) del
    // token JWT proporcionado.
    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }


    //isTokenValid(String token, UserDetails userDetails): Verifica si el token JWT es
    // válido para un usuario determinado. Comprueba si el nombre de usuario del token
    // coincide con el nombre de usuario del usuario proporcionado (userDetails).
    // También verifica si el token ha expirado utilizando el método isTokenExpired(token).
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username=getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

    //getAllClaims(String token): Obtiene todas las reclamaciones del token JWT proporcionado.
    // Utiliza la clave secreta para validar la firma del token y luego extrae y devuelve todas
    // las reclamaciones del cuerpo del token.
    private Claims getAllClaims(String token)
    {
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //getClaim(String token, Function<Claims,T> claimsResolver): Obtiene una reclamación
    // específica del token JWT utilizando una función (claimsResolver) que toma las
    // reclamaciones como argumento y devuelve un resultado de tipo T.
    public <T> T getClaim(String token, Function<Claims,T> claimsResolver)
    {
        final Claims claims=getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //getExpiration(String token): Obtiene la fecha de expiración del token JWT proporcionado.
    private Date getExpiration(String token)
    {
        return getClaim(token, Claims::getExpiration);
    }

    //isTokenExpired(String token): Verifica si el token JWT ha expirado comparando
    // la fecha de expiración con la fecha actua
    private boolean isTokenExpired(String token)
    {
        return getExpiration(token).before(new Date());
    }
}
