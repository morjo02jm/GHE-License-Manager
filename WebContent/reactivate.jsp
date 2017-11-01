<%@ page import="com.ca.RunCommand"%>
<html>
<head>
<title>Reactivate GitHub Suspended Accout</title>
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
        out.println("Must provide Github server name !<br><br>");
    } else {
        out.println("<br>GitHub Server: <b>"+server+"</b><br><br>");
    }
%>
<%
String cmd = "unsuspend "+name+" "+server;
String result = RunCommand.execute(cmd);
out.println (result);
System.out.println (result + " - " + new java.util.Date());
%>
<% out.println("<br>"); %>
<%= new java.util.Date() %>

<%-- END --%>

</body>
</html>
