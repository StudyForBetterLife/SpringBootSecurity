package com.cos.security1.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.oauth.provider.FacebookUserInfo;
import com.cos.security1.oauth.provider.GoogleUserInfo;
import com.cos.security1.oauth.provider.OAuth2UserInfo;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService implements Customizer<OAuth2LoginConfigurer<org.springframework.security.config.annotation.web.builders.HttpSecurity>.UserInfoEndpointConfig> {

    @Autowired
    private UserRepository userRepository;

    // 구글 oauth 로그인 후 받은 userRequest 데이터에 대한 후처리되는 함수
    // loadUser 메소드의 반환값 PrincipalDetails이 Security Session 정보로 들어간다.
    // loadUser 메소드 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration: " + userRequest.getClientRegistration()); // registrationId로 어떤 Oauth로 로그인했는지 알 수 있음
        System.out.println("getAccessToken: " + userRequest.getAccessToken().getTokenValue());

        // 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인 완료 -> code 리턴(Oauth-Client 라이브러리)-> accesstoken 요청
        // userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원프로필을 받아준다
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("getAttributes: " + oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getRegistrationId(); // google

        OAuth2UserInfo oAuth2UserInfo = null;
        if (provider.equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (provider.equals("facebook")) {
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else {
            System.out.println("구글과 페이스북 로그인만 지원해요");
        }

        assert oAuth2UserInfo != null;
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            userRepository.save(User.builder()
                    .username(username)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build());
        }

        // 1. 일반 로그인시 -> Security Session의 Authentication 이 담고 있는 객체 PrincipalDetails에는 User와 null이 담긴다.
        // 2. oauth 로그인시 -> PrincipalDetails에는 User와 Map<String, Object>의 유저 정보가 담긴다.
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }

    @Override
    public void customize(OAuth2LoginConfigurer<HttpSecurity>.UserInfoEndpointConfig userInfoEndpointConfig) {

    }
}
