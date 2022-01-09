package com.cos.security1.auth;


import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 .loginProcessingUrl("/login")
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어있는 loadUserByUsername 함수가 실행됨
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // String username : html input 태그의 name 속성이름을 username으로 설정해야한다.
    // 시큐리티 session => Authentication => UserDetails
    // loadUserByUsername 메소드의 리턴값 UserDetails이 Authentication 인자로 들어간다.
    // Authentication은 시큐리티 session의 인자로 들어간다.
    // 시큐리티 Session(Authentication(UserDetails)))
    // loadUserByUsername 메소드 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if (username != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
