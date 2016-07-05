<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Reactivate GitHub Suspended Account</title>
</head>
<body>
<%-- START --%>
<%
 out.println("<b>Reactivate GitHub Suspended Account</b><p>");
String name = request.getParameter("name");
String server = request.getParameter("server");
 if (name == null || name == "") {
        out.println("Must provide your PMF key!<br>");
    } else {
        out.println("User: <b>"+name+"</b>");
    }
  if (server == null || server =="") {
        out.println("Must provide GitHub server name !<br><br>");
    } else {
        out.println("<br>GitHub Server: <b>"+server+"</b><br><br>");
    }
%>
<%
String cmd = "unsuspend "+name+" "+server;
out.println (RunCommand.execute(cmd));
%>
<% out.println("<br>"); %>
<%= new java.util.Date() %>
<%-- END --%>
</body>
</html>