package com.seguriry.demo.Jwt;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    //. Representa el servicio de Spring Security que se
    // utiliza para cargar los detalles de usuario (como nombre
    // de usuario, contraseña y roles) para la autenticación.
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String token = getTokenFromRequest(request);
        final String username;

        if (token==null)
        {
            filterChain.doFilter(request, response);
            return;
        }

        //para obtener el nombre del usuario
        username=jwtService.getUsernameFromToken(token);

        if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            // trae los detalles del usuario
            UserDetails userDetails=userDetailsService.loadUserByUsername(username);

            // verifica el token
            if (jwtService.isTokenValid(token, userDetails))
            {
                // si es valido crea una instancia de UsernamePasswordAuthenticationToken
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());


                //manda mas detalles

                //La clase WebAuthenticationDetailsSource es una implementación de AuthenticationDetailsSource
                // proporcionada por Spring Security. Se utiliza para construir y proporcionar
                // los detalles de autenticación específicos de la solicitud actual.
                // Estos detalles incluyen información adicional sobre la solicitud de
                // autenticación, como la dirección IP del cliente, la dirección URL de la
                // solicitud, el agente de usuario (navegador) utilizado, etc.

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // establece una nueva autentificacion
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }

        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer "))
        {
            return authHeader.substring(7);
        }
        return null;
    }



}
