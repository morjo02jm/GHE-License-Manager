#    The script executes user reactivation part of the GitHub Enterprise license sharing policy.  
#    Grace 5/12/2016

use Net::LDAP;
use Net::LDAP::Entry;
use JSON qw( decode_json );
use strict;

die ("Usage: $0 PMFKey GitHub_Server\n") if ($#ARGV != 1);
my $pmfkey = $ARGV[0] or die "Must provide PMF key!\n";
my $gheserver = $ARGV[1] or die "Must provide GitHub server!\n";
my $group = "Development-Tools-Access-Group";
my $gheusr = "toolsadmin";
my $ghepw = "";
my $ldapusr = "toolsadmin";
my $ldappw = "";
my $logfile = ".\/GHEReactivateUser.log";
$logfile = $ENV{'CATALINA_HOME'} . "\/logs\/" . "GHEReactivateUser.log" if ($ENV{'CATALINA_HOME'});
my ($ldap, $mesg, $tstr);
open (LOG, ">> $logfile") or die $!;

my $suspended = isSuspendedUser($pmfkey);
if ($suspended == 1)
{
  $ldap = Net::LDAP->new ( "usildc05.ca.com" ) or die "$@";
  $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=ITC Hyderabad,dc=ca,dc=com", password => $ldappw);
#  $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=north america,dc=ca,dc=com", password => $ldappw);
  $mesg->code && die $mesg->error;
  my $userdn = LDAPSearch ($pmfkey);
  my $groupdn = LDAPGroupSearch ("$group");
  if ($userdn && $groupdn)
  {
 #   LDAPGroupUserSearch ("$pmfkey", "$group"); # trust suspending user process, check before add instead
    LDAPGroupAdd ("$userdn", "$groupdn");
  }
  $ldap->unbind;
}
elsif ($suspended == 2) 
{
  print "Could not connect to host: $gheserver!";
  printlog ("Could not connect to host: $gheserver! - " . printtime());
}
elsif ($suspended == 0) 
{
  print "$pmfkey is not a suspended GitHub account!";
  printlog ("Account $pmfkey is not a suspended GitHub account! - " . printtime());
}
close LOG;
exit 0;

sub isSuspendedUser {
  my $user = shift;
  #get around github cache 
  my $APISuspended = "https:\/\/" . $gheserver . "\/api\/v3\/users\/" . $user; 
  my $suspended = curlrun ($APISuspended);
  return 2 if (grep (/connection error/, $suspended));  
  my $decoded = decode_json($suspended) ;
  return 0 if (! $decoded->{'suspended_at'});
  return 1;
}

sub curlrun {
  my $url = shift;
  my $jcmd = "curl -s -u $gheusr:\"$ghepw\" $url";
  my $jdata = `$jcmd`;
  if ($? > 0)
  {
    return "connection error";
  }
  else 
  {
    $jdata = `$jcmd`;
  }
  return $jdata;
}


sub printlog {
  print LOG "@_\n";
}

sub printtime {
  $tstr = localtime();
  return $tstr . "\n";
}

sub getdate {
  my ($d,$m,$y) = (localtime)[3,4,5];
  my $ymd = sprintf '%d%02d%02d', $y+1900, $m+1, $d;
  return $ymd;
}


sub LDAPSearch
{
   my ($searchString) = shift;
   my $userdn;
   my $base = "dc=ca,dc=com"; 

   $mesg = $ldap->search ( base    => "$base",
                           filter  => "(&(!(objectclass=computer))(&(cn=$searchString)(objectclass=person)))"
                         );
   $mesg->code && die $mesg->error;
   if ($mesg->count == 0)  {
      print "$searchString is not a valid domain user!";
      printlog ("$searchString is not a valid domain user! - " . printtime());
   }
   elsif ($mesg->count > 1)  {
     print "$searchString is not unique\n";
	 printlog ("$searchString is not unique\n");
   }
   else {
     my @entries = $mesg->entries;
     $userdn = $entries[0]->dn;
   }
   return $userdn;
}

sub LDAPGroupSearch
{
   my ($searchString) = shift;
   my $groupdn;

   my $base = "cn=$searchString,ou=groups,OU=North America,dc=ca,dc=com";  # Better performance ...
   $mesg = $ldap->search ( base    => "$base",
                           filter  => "(&(objectClass=group))"
                         );
   $mesg->code && die $mesg->error;
   if ($mesg->count == 0)  {
      print "$searchString is not a valid DL\n";
   }
   elsif ($mesg->count > 1)  {
     print "$searchString is not unique\n";
   }
   else {
     my $entry = $mesg->entry(0);
	 $groupdn = $entry->dn;
   }
  return $groupdn;
}

sub LDAPGroupAdd {
  my ($memberdn, $groupdn) = @_;
  $mesg = $ldap->modify ($groupdn,
		add => {member => "$memberdn" }
		);

  if ($mesg->code == 68) #entry exists error
  {
    print "Account $pmfkey is already in the LDAP group.";  
    printlog ("Account $pmfkey is already in the LDAP group. - " . printtime());
  }
  if (!$mesg->code)
  {
    print "Account $pmfkey is reactivated. Please note if the account is not used for GitHub activities, it may get suspended again in 24 hours.";
    printlog ("Account $pmfkey is reactivated. - " . printtime());	
  }
}

