package com.cos.security1.controller;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller // view를 리턴하겠다는 어노테이션
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * Spring Security 속에 Security Session이 존재한다.
     * Security Session에 들어갈 수 있는 타입은 Authentication 객체 뿐이다.
     * Authentication 객체는 controller 에서 DI를 통해 사용할 수 있다.
     * Authentication 객체 안에 들어갈 수 있는 객체 타입에는 2가지가 존재한다.
     * 1. UserDetails 타입 : 일반적인 로그인 시, UserDetails 타입 객체가 Authentication 객체 안에 들어간다
     * 2. OAuth2User 타입 : Oauth 로그인 시, OAuth2User 타입 객체가 Authentication 객체 안에 들어간다
     * <p>
     * 따라서 UserDetails, OAuth2User 모두를 implements 하는 클래스를 Authentication 객체에 담도록 한다.
     * -> PrincipalDetails 클래스에 UserDetails, OAuth2User 모두를 implements 하여 일반로그인, Oauth로그인이 될 경우 모두 다운캐스팅가능하도록 한다.
     */

    @GetMapping("/test/login")
    public @ResponseBody
    String loginTest(
            Authentication authentication,
            @AuthenticationPrincipal PrincipalDetails userDetails) { // Authentication 객체는 DI를 통해 사용가능
        // 1-1. Authentication 객체를 DI와 다운캐스팅을 통해 PrincipalDetails 객체를 얻을 수 있고
        // oauth 로그인시 PrincipalDetails으로 다운캐스팅이 안된다.
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication: " + principal.getUser());

        // 1-2. @AuthenticationPrincipal 어노테이션을 통해 PrincipalDetails 객체를 얻을 수 있다
        System.out.println("userDetails: " + userDetails.getUser());
        return "세션 정보 확인";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody
    String testOAuthLogin(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oAuth) { // Authentication 객체는 DI를 통해 사용가능
        // oauth 로그인시 OAuth2User로 다운캐스팅 해야한다.
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication: " + oauth2User.getAttributes());

        // 다운캐스팅 과정없이 @AuthenticationPrincipal 어노테이션으로 OAuth2User객체를 얻을 수 있다
        System.out.println("oauth2User: " + oAuth.getAttributes());
        return "OAuth 세션 정보 확인";
    }

    @GetMapping({"", "/"})
    public String index() {
        // mustache 기본 폴더 src/main/resources/
        // viewResolver 설정 : templates(prefix), mustache(suffix) 생략 가능
        return "index"; // src/main/resources/templates/index.mustache
    }

    // Oauth 로그인 또는 일반 로그인시에도 PrincipalDetails 객체로 유저 정보를 받을 수 있다.
    // loginTest(), testOAuthLogin() 메소드처럼 로그인 유형에 따라 분기 처리할 필요가 없다
    // @AuthenticationPrincipal 어노테이션은
    @GetMapping("/user")
    public @ResponseBody
    String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails: " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody
    String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody
    String manager() {
        return "manager";
    }

    // 스프링 시큐리티가 /login url을 낚아채간다
    // SecurityConfig 파일 작성후 더이상 낚아채지 않음
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword); // 암호화되지 않은 패스워드로 시큐리티 로그인 불가능하기 때문
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN") // ROLE_ADMIN 권한이 있는 사용자만 접근할 수 있는 주소
    @GetMapping("/info")
    public @ResponseBody
    String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // ROLE_MANAGER 또는 ROLE_ADMIN 권한이 있는 사용자만 접근 가능
    @GetMapping("/data")
    public @ResponseBody
    String data() {
        return "데이터 정보";
    }
}

