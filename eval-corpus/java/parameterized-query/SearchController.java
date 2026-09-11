import java.sql.Connection;
import java.sql.PreparedStatement;
class SearchController {
  void handle(HttpServletRequest request, Connection connection) throws Exception {
    String name = request.getParameter("name");
    PreparedStatement statement = connection.prepareStatement("SELECT id FROM users WHERE name = ?");
    statement.setString(1, name);
    statement.executeQuery();
  }
}
