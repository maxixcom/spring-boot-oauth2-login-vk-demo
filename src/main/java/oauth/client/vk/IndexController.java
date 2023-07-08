package oauth.client.vk;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class IndexController {

    @GetMapping("/")
    public ResponseEntity<?> indexAction(@AuthenticationPrincipal OAuth2User principal) {

        return ResponseEntity.ok(Map.of(
                "authenticated", "user",
                "principal", principal
        ));
    }
}
