package kr.demonic.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * 소셜 로그인 담당 컨트롤러
 */
@Controller
public class LoginOauth2Controller {
    @RequestMapping(path={"/", "/main"})
    public String main(){
        return "main";
    }

    // 기본 URL 설정
    private static String authorizationRequestBaseUri = "/oauth2/authorization";
    Map<String, String> oauth2AuthenticationUrls = new HashMap<>();

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    // 로그인 시도 이후 받아온 정보
    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    // 로그인 화면
    @GetMapping("/oauth/login")
    public String login(Model model) {
        Iterable<ClientRegistration> clientRegistrations = null;
        ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository)
                .as(Iterable.class);
        if (type != ResolvableType.NONE &&
                ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
            clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
        }

        clientRegistrations.forEach(registration ->
                oauth2AuthenticationUrls.put(registration.getClientName(),
                        authorizationRequestBaseUri + "/" + registration.getRegistrationId()));
        model.addAttribute("urls", oauth2AuthenticationUrls);

        return "oauth/login";
    }

    // 로그인 성공 후
    @GetMapping("/oauth/login_success")
    public String login_success(Model model, OAuth2AuthenticationToken authentication){
        OAuth2AuthorizedClient client = authorizedClientService
                .loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName()
                );

        String userInfoEndpointUri = client.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUri();

        if (!StringUtils.isEmpty(userInfoEndpointUri)) {
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + client.getAccessToken().getTokenValue());


            HttpEntity entity = new HttpEntity(headers);
            ResponseEntity<Map> response = restTemplate.exchange(siteUrlCustoom(authentication.getAuthorizedClientRegistrationId(), userInfoEndpointUri), HttpMethod.GET, entity, Map.class);
            Map userAttributes = response.getBody();

            model.addAttribute("userInfo", userAttributes);
        }

        return "oauth/login_success";
    }

    /**
     * 소셜 종류에 따라 URL 구성 변경
     * @param site
     * @return
     */
    protected String siteUrlCustoom(String site, String baseUrl){
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(baseUrl);

        if(site.equals("facebook")){
            uriBuilder.queryParam("fields", "name,email,picture,locale");
        }

        return uriBuilder.toUriString();
    }
}
