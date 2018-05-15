package com.meklit.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity

public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
        //Using the bean for the password encoder, instead of putting it in the configure method.
        //The bean is always available in the context path once the application is run.
    PasswordEncoder passwordEncoder()
    {

        return new BCryptPasswordEncoder();
    }

    //Pass a repository to the SSUDS, so that only one repository is used for authentication - instead of creating one every time


    //Override the userDetailServiceBean method to return a new SSUDS to authenticate with



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and().httpBasic();



    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
//Set up in memory authentication. REMOVE THIS for production deployments
        auth.inMemoryAuthentication().withUser("user")
                .password(passwordEncoder().encode("password")).authorities("USER")
                .and()
                .passwordEncoder(passwordEncoder());

        //Get user details from the SS User Details Service for the user who is trying to log in.
        auth.userDetailsService(userDetailsServiceBean()).passwordEncoder(passwordEncoder());


    }
}