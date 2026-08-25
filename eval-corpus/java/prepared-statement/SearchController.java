import java.sql.Connection;
import java.sql.PreparedStatement;
class SearchController {
  void handle(HttpServletRequest request, Connection connection) throws Exception {
    String sql = request.getParameter("sql");
    PreparedStatement statement = connection.prepareStatement(sql);
    statement.executeQuery();
  }
}
