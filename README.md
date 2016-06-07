# ghe-license-policy
Implement GHE license sharing policy
ghelp.pl executes suspending account function - remove a account from its corresponding LDAP group and suspend it from GitHub server. 
A license is release without waiting on GitHub/LDAP sync process.  
unsuspend.pl executes reactivating a suspended GitHub account - add a suspended GitHub account ID (PMF key) into the corresponding 
LDAP group. 
Unsuspend function will be made as user self-service so it will run as an app in Tomcat. 

