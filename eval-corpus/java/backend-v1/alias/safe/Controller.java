import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.sql.Connection;
import java.nio.file.*;
import org.apache.commons.lang3.SerializationUtils;
class Controller {
  @GetMapping("/review")
  void handle(@RequestParam String value, Connection db, RestTemplate client) throws Exception {
    String alias = value;
    String command = "fixed";
    Runtime.getRuntime().exec(command);
  }
}
