import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.sql.Connection;
import java.nio.file.*;
import org.apache.commons.lang3.SerializationUtils;
class Controller {
  @GetMapping("/review")
  void handle(@RequestParam String value, Connection db, RestTemplate client) throws Exception {
    db.prepareStatement("SELECT * FROM records WHERE id=?").setString(1, value);
  }
}
