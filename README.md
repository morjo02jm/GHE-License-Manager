# ghe-license-policy
Implement GHE license sharing policy
ghelp.pl executes suspending account function - remove a account from its corresponding LDAP group and suspend it from GitHub server. A license is release without waiting on GitHub/LDAP sync process.  
usage: perl ghelp.pl 
Usage: ghelp.pl [options] [values]
The script executes GHE license sharing policy.

  -h    print this help page

  -v    verbose mode

  -s    [value required] GitHub server, e.g. github-isl-01.ca.com, default GitHub development server

  -t    [value required] available minimum GitHub license seats to enforce sharing policy, default value 2250

  -w    [value required] nubmer of days in whcih a user is inactive while receiving warning message, default 60

  -d    [value required] number of days in which a user is inactive while the account is suspended, default 90

  -e    [value required] exception account file, default exceptions.txt

  -gheusr       [value required] GitHub admin account user name

  -ghepw        [value required] GitHub admin account password

  -ldapgroup    [value required] GitHub LDAP user group name, default Development-Tools-Access-Group

  -ldapusr      [value required] LDAP group owner ID or an account with update access to the LDAP group, default toolsadmin

  -ldappw       [value required] ldapusr account password

  -rs   [value required] GitHub shell script to query users, default custom-all-users.sh

  -cp   [value required] script to copy over to GitHub virtual appliance

  -key  [value required] RSA key to access GitHub through SSH

  -pubkey       [value required] public RSA key to access GitHub through SSH

  -wo   warning only and no users will be suspended

  -u    print license and user statistics only

unsuspend.pl executes reactivating a suspended GitHub account - add a suspended GitHub account ID (PMF key) into the corresponding LDAP group. 
Unsuspend function will be made as user self-service so it will run as an app in Tomcat. 
Usage: unsuspend.pl PMFKey GitHub_Server

