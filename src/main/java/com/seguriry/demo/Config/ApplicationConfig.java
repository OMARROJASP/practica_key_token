package com.seguriry.demo.Config;

import com.seguriry.demo.User.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


//configura diversos componentes para la autenticación en una
// aplicación basada en Spring Security



//@Configuration: Indica que esta clase es una clase de configuración
// de Spring y define beans (componentes) que se utilizarán en la aplicación.
@Configuration
//@RequiredArgsConstructor: Es una anotación de Lombok que genera un constructor con todos
// los campos marcados como final en la clase. En este caso, se utiliza para inyectar el
// repositorio UserRepository como una dependencia a través del constructor.
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository userRepository;

    //authenticationManager(AuthenticationConfiguration config): Define un bean para el AuthenticationManager.
    // Utiliza el parámetro AuthenticationConfiguration para obtener el AuthenticationManager
    // configurado automáticamente por Spring Security. El AuthenticationManager es un componente
    // fundamental en la autenticación de Spring Security, y es responsable de validar las
    // credenciales de los usuarios
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception
    {
        return config.getAuthenticationManager();
    }
//authenticationProvider(): Define un bean para el AuthenticationProvider. Utiliza un objeto
// DaoAuthenticationProvider, que es una implementación de AuthenticationProvider proporcionada
// por Spring Security. Configura este proveedor con el servicio userDetailService() y el
// codificador de contraseñas passwordEncoder(). El AuthenticationProvider se
// utiliza para buscar y validar la información de autenticación de los usuarios.

    @Bean
    public AuthenticationProvider authenticationProvider()
    {
        DaoAuthenticationProvider authenticationProvider= new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    //passwordEncoder(): Define un bean para el codificador de contraseñas BCryptPasswordEncoder.
    // Este codificador es una implementación de PasswordEncoder proporcionada por Spring Security.
    // Se utiliza para codificar las contraseñas de los usuarios antes de almacenarlas en la base de
    // datos y para comparar las contraseñas ingresadas por los usuarios durante el proceso de
    // autenticación.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    //userDetailService(): Define un bean para el servicio UserDetailsService. Este servicio es
    // una interfaz proporcionada por Spring Security y se utiliza para cargar los detalles de
    // un usuario (como nombre de usuario, contraseña y roles) para el proceso de autenticación.
    // En este caso, se proporciona una implementación anónima de UserDetailsService que busca
    // el usuario en el repositorio UserRepository basándose en el nombre de usuario. Si no se
    // encuentra el usuario, se lanza una excepción UsernameNotFoundException.
    @Bean
    public UserDetailsService userDetailService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("User not fournd"));
    }
}
