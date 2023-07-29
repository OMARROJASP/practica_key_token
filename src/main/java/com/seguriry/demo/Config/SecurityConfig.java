package com.seguriry.demo.Config;

import com.seguriry.demo.Jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//En Spring Security, los filtros son componentes que se utilizan para interceptar y procesar
// solicitudes HTTP antes o después de que lleguen a un punto específico del proceso de seguridad.
// Estos filtros permiten aplicar diferentes funcionalidades relacionadas con la seguridad, como
// autenticación, autorización, manejo de sesiones, entre otros.


import static org.springframework.security.config.Customizer.withDefaults;

//@Configuration: Indica que esta clase es una clase de configuración de Spring y define beans
// (componentes) que se utilizarán en la aplicación.

//@EnableWebSecurity: Habilita la configuración de seguridad de Spring Security para la aplicación.
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf ->
                        csrf.disable()
                )// Deshabilita la protección CSRF (Cross-Site Request Forgery)
                // en la configuración de seguridad.
                .authorizeHttpRequests(authRequest ->
                        authRequest
                                .requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated()
                        )

                //sessionManagement(sessionManager -> sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS)): Configura la
                // administración de sesiones para la política STATELESS. Esto significa que la aplicación
                // no mantendrá ninguna información de sesión en el servidor y, en su lugar, utilizará tokens
                // JWT para manejar la autenticación y autorización de manera sin estado.
                .sessionManagement(sessionManager->
                        sessionManager
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //authenticationProvider(authProvider): Configura el proveedor de autenticación
                // authProvider que se ha definido en ApplicationConfig. El proveedor de
                // autenticación se utiliza para validar las credenciales de los usuarios
                // durante el proceso de autenticación.
                .authenticationProvider(authProvider)
                //addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class):
                // Agrega el filtro jwtAuthenticationFilter antes del filtro UsernamePasswordAuthenticationFilter.
                // Esto asegura que el filtro personalizado JwtAuthenticationFilter se ejecute antes de que Spring
                // Security intente autenticar a los usuarios utilizando el filtro
                // UsernamePasswordAuthenticationFilter, lo que permite la autenticación basada en tokens JWT.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
    //.addFilterBefore(...): Este método se utiliza para agregar el filtro personalizado
    // jwtAuthenticationFilter antes del filtro UsernamePasswordAuthenticationFilter en
    // la cadena de filtros de Spring Security.
}
