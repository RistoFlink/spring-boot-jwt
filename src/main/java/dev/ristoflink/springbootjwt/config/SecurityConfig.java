package dev.ristoflink.springbootjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //create a default user to test the app with
    @Bean
    public InMemoryUserDetailsManager users(){
        return new InMemoryUserDetailsManager(
                User.withUsername("rf")
                        .password("{noop}password")
                        .authorities("read")
                        .build()
        );
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        return http
                .csrf(AbstractHttpConfigurer::disable) //disable Cross-Site Request Forgery CSRF
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated() //user should be authenticated for any request in the app
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //Spring Security will never create an HttpSession/use it to obtain the Security Context
                .httpBasic(Customizer.withDefaults()) //authenticate users with HttpBasic
                .build();
    }
}
