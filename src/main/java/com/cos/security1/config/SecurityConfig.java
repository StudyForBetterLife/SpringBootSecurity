package com.cos.security1.config;

import com.cos.security1.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// secured,PreAuthorize, PostAuthorize 어노테이션 활성화
// Secured, PreAuthorize, PostAuthorize 어노테이션은 특정 메소드에 권한을 설정하고자 할 때 사용한다.
// 전역으로 권한을 설정하고 싶다면 configure 메소드를 활용한다.

public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 해당 메소드의 리턴되는 객체를 IoC로 등록해준다
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만 되면 접근할 수 있는 주소
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll() // 스프링 시큐리티가 더이상 /login url을 낚아채지 않는다.
                .and()
                .formLogin()
                .loginPage("/loginForm") // 권한이 없는 페이지 접근시 /login url로 전환된다.
//                .usernameParameter("username2") // login 페이지의 사용자이름 input 태그의 name 속성값을 지정한다
                .loginProcessingUrl("/login") // /login 주소가 호출되면, 스프링 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                .defaultSuccessUrl("/") // 로그인이 성공적으로 이뤄지면 / 주소로 간다
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                // 구글 로그인이 완료가 되면 -> accessToken & 사용자 프로필 정보를 받는다.
                // 1.코드받기(인증이 된것) 2.엑세스 토큰(구글 계정에 접근할 수 있는 권한)
                // 3. 사용자 프로필 가져온다
                // 4-1. 사용자 정보를 토대로 회원가입 자동 진행시키기도함
                // 4-2. 추가적인 사용자 정보를 받기 위한 추가적인 정보기입 페이지가 필요할 수 있다.
                .userInfoEndpoint(principalOauth2UserService)
        ;
    }
}
