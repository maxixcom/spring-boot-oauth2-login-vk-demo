package oauth.client.vk.security.vk;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@NoArgsConstructor
@Getter
@Setter
public class VkUsersGetResponse {
    private List<Map<String, Object>> response;
}
