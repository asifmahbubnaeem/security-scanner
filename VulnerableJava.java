// VulnerableJava.java

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableJava extends HttpServlet {

    // Hardcoded DB credentials
    private static final String DB_USER = "root";
    private static final String DB_PASS = "Password123!";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String user = request.getParameter("user");
        String cmd = request.getParameter("cmd");

        // SQL Injection
        try (Connection conn = DriverManager.getConnection(
                     "jdbc:mysql://localhost:3306/app_db", DB_USER, DB_PASS);
             Statement stmt = conn.createStatement()) {

            String sql = "SELECT * FROM users WHERE username = '" + user + "'";
            ResultSet rs = stmt.executeQuery(sql);

            response.setContentType("text/html");
            while (rs.next()) {
                // Reflected XSS
                response.getWriter().println("<p>User: " + user + "</p>");
            }
        } catch (SQLException e) {
            throw new ServletException(e);
        }

        // Command injection
        if (cmd != null) {
            Process p = Runtime.getRuntime().exec("ls " + cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        }
    }
}

