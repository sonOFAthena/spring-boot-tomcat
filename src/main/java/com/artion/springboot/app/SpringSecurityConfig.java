package com.artion.springboot.app;

import com.artion.springboot.app.auth.handler.LoginSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private LoginSuccessHandler successHandler;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Autowired
    public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception{

        /*
        //USANDO inMemoryAuthentication()
        PasswordEncoder encoder = this.passwordEncoder;
        User.UserBuilder users = User.builder().passwordEncoder(encoder::encode);

        builder.inMemoryAuthentication()
                .withUser(users.username("admin").password("asdfg").roles("ADMIN", "USER"))
                .withUser(users.username("jose").password("asdfg").roles("USER"));

         */

        // USANDO JDBC
        builder.jdbcAuthentication().dataSource(dataSource)
                .passwordEncoder(passwordEncoder)
                .usersByUsernameQuery("SELECT username,password,enabled FROM users WHERE username=?")
                .authoritiesByUsernameQuery("SELECT u.username, a.authority FROM authorities a INNER JOIN users u on (a.user_id=u.id) WHERE u.username=?");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar").permitAll()
//                .antMatchers("/ver/**").hasAnyRole("USER")
//                .antMatchers("/upload/**").hasAnyRole("USER")
//                .antMatchers("/form/**").hasAnyRole("ADMIN")
//                .antMatchers("/eliminar/**").hasAnyRole("ADMIN")
//                .antMatchers("/factura/**").hasAnyRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                    .formLogin()
                        .successHandler(successHandler)
                        .loginPage("/login")
                    .permitAll()
                .and()
                    .logout().permitAll()
                .and()
                .exceptionHandling().accessDeniedPage("/error_403");

    }
}
