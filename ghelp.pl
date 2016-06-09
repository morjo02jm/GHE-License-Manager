#!/usr/bin/perl

############################################################################
# the script executes suspending use part of the GHE license sharing policy. 
# Grace Gao - 5/3/2016 for review
############################################################################

use strict;
use warnings;
use Net::SSH2;
use Net::LDAP;
use Net::LDAP::Util qw(ldap_error_text);
use Net::LDAP::Entry;
use Net::SMTP;
use MIME::Lite;
use JSON qw( decode_json );
use Cwd;
use Getopt::Long;

open STDERR, ">&STDOUT";
select STDERR; $| = 1;
select STDOUT; $| = 1;

use vars qw($opt_h $opt_v $opt_s $opt_t $opt_w $opt_d $opt_e $opt_wo $opt_u $opt_key $opt_pubkey $opt_rs $opt_cp $opt_gheusr $opt_ghepw $opt_ldapusr $opt_ldappw $opt_ldapgroup);

GetOptions('h', 'v', 'wo', 'u', 's=s', 't=i', 'w=i', 'd=i', 'e=s', 'rs=s', 'key=s', 'pubkey=s', 'cp=s', 'gheusr=s', 'ghepw=s', 'ldapusr=s', 'ldasppw=s', 'ldapgroup=s') ||  printusage();
my $gheserver = $opt_s || "github-isl-dev-01.ca.com";
my $threshold = $opt_t || 2250; #total 2250 seats
my $idle = $opt_d || 90;
my $warning = $opt_w || 60;
my $exfile = $opt_e || "exceptions.txt";
my $gheusr = $opt_ldapusr || "toolsadmin";
my $ghepw = $opt_ldappw || "";
#my $ldapusr = $opt_ldapusr || "toolsadmin"; 
#my $ldappw = $opt_ldappw || "";
# my $dl = $opt_ldapgroup || "Development-Tools-Access-Group";
my $ldapusr = $opt_ldapusr || "harvestcscr";
my $ldappw = $opt_ldappw || "";
my $dl = $opt_ldapgroup || "RTC-CCM6 Users"; #test due to LDAP dev environment is not accessible 
my $rscript = $opt_rs || "custom-all-users.sh";
my $cp = $opt_cp || $rscript;
my $key = $opt_key || "C:\\Users\\gaoyu01\\.ssh\\id_rsa";
my $pubkey = $opt_pubkey || "C:\\Users\\gaoyu01\\.ssh\\id_rsa.pub";
my $gpath = "c:\\git\\bin";
my ($logfile, $usage, $htmlusage, $json, $ldap, $mesg, %candidates, %generic, %exceptions, @admins);

sub printusage {
  print "\nUsage: $0 [options] [values]\n" .
  "The script executes GHE license sharing policy.\n
  -h\tprint this help page\n
  -v\tverbose mode\n
  -s\t[value required] GitHub server, e.g. github-isl-01.ca.com, default GitHub development server\n
  -t\t[value required] available minimum GitHub license seats to enforce sharing policy, default value 2250\n
  -w\t[value required] nubmer of days in whcih a user is inactive while receiving warning message, default 60\n
  -d\t[value required] number of days in which a user is inactive while the account is suspended, default 90\n
  -e\t[value required] exception account file, default exceptions.txt\n
  -gheusr\t[value required] GitHub admin account user name\n
  -ghepw\t[value required] GitHub admin account password\n
  -ldapgroup\t[value required] GitHub LDAP user group name, default Development-Tools-Access-Group\n
  -ldapusr\t[value required] LDAP group owner ID or an account with update access to the LDAP group, default toolsadmin\n
  -ldappw\t[value required] ldapusr account password\n
  -rs\t[value required] GitHub shell script to query users, default custom-all-users.sh\n
  -cp\t[value required] script to copy over to GitHub virtual appliance\n
  -key\t[value required] RSA key to access GitHub through SSH\n
  -pubkey\t[value required] public RSA key to access GitHub through SSH\n
  -wo\twarning only and no users will be suspended\n
  -u\tprint license and user statistics only\n
  ";
  exit 0;
}

# prepare REST API entries
my $APILicenseUsage = "https:\/\/" . $gheserver . "\/api\/v3\/enterprise\/settings\/license";
my $APIDormantUsers = "https:\/\/" . $gheserver . "\/stafftools/reports/dormant_users.csv";
my $APISuspendedUsers = "https:\/\/" . $gheserver . "\/stafftools/reports/suspended_users.csv";

sub getdate {
  my ($d,$m,$y) = (localtime)[3,4,5];
  my $ymd = sprintf '%d%02d%02d', $y+1900, $m+1, $d;
  return $ymd;
}

sub getpastdate {
  my $span = shift;
  my $past_days = $span * 24 * 60 * 60;
  my ($d,$m,$y) = (localtime(time - $past_days))[3..5];
  my $pastdate = sprintf '%d-%02d-%02d', $y+1900, $m+1, $d;
  return $pastdate;
}

sub printv {
 $opt_v && print("@_\n");
}

sub printlog {
  print LOG "@_\n";
}

sub printtime {
  my $tstr = localtime();
  return $tstr . "\n";
}

sub ispmf {
  my $pmf = shift;
  return 1 if ($pmf =~ m/.{5}\d{2}\s*/);
  return 0;
}

sub isexception {
  my $pmf = shift;
  my @exceptionslist;
  open (EX, "<$exfile");
  @exceptionslist = <EX>;
  close EX;
  return 1 if (grep(/$pmf/i, @exceptionslist));
  return 0;
}

sub curlrun {
  my $url = shift;
  my $jcmd = "curl -s -u $gheusr:pw $url"; # hide pw
  my $jsondata = `curl -s -u $gheusr:\"$ghepw\" $url`; #GitHub tends to cache first
  printlog("Extracting current GHE license usage ...");
  printv("Extracting current GHE license usage ...\n");
#  printv("Executing $jcmd\n");
  $jsondata = `curl -s -u $gheusr:\"$ghepw\" $url`;
  my $rc = $?;
  if (! $rc)
  {
    my $decoded = decode_json($jsondata) ;
    return $decoded;
  }
  printv ("Either your user name, password or server name is not right. Please check it and try again.\n");
  print "Either your user name, password or server name is not right. Please check it and try again.\n";
  exit 1;
}

sub QueryDormantUsers {
  my $rcm = "sudo bash -x /tmp/$rscript ";
  my @users;
  my $fname = "";
  my $fn = "";
  my $ssh2 = Net::SSH2->new();
  my ($chan, $cmd);
# note SSH2 32k channel I/O limitation and then strange behaviour in scp_get(), so scp system call is used. 
# SSH2 is a little buggy. This part could be rewritten when time permits. 
# enhancement if needed
  if ($opt_cp)
  {
    $cmd = "$gpath\\scp -i $key -P 122 $cp admin\@$gheserver:/tmp/";
	`$cmd` && die "$!";
  }
  printv ("Querying User Activities ...");
#  $ssh2->debug(1);
  $ssh2->connect("$gheserver", 122) or die $!;
  if ($ssh2->auth_publickey("admin", "$pubkey", "$key")) 
  {
      $chan = $ssh2->channel();
#	  $chan->blocking(0);
      $chan->exec("$rcm");
       while (<$chan>)
       {
         $fn .= $_;
		 last if grep (/Done\./, $fn);
       }
	  $chan->close;
      $ssh2->disconnect;
  }
  $fn =~ m/Saving list of users to \'\/tmp\/(.+)\'\.\.\./;
  $fname = $1;
  $cmd = "$gpath\\scp -i $key -P 122 admin\@$gheserver:/tmp/$fname .";
  `$cmd` && die "$!";
  open (IN, "<$fname") or die "$!";
  @users = <IN>;
  close IN;
  printv ("Non_Admin Candidates:");
  printlog ("Non_Admin Candidates:");
#  shift @users if (@users); # skip header
  foreach my $user (@users)
  {
     next if (!$user);
     chomp $user;
	 $user =~ s/,\\N/,\"\\N\"/g; #capture account w/o email
     my @fields = split "\",\"", $user;
     my $id = substr $fields[0], 1;
	 $id =~ s/-/\$/g if (ispmf($id));
	 my $email = $fields[1];
	 my $role = $fields[2];
     my $status = $fields[6];
     my $lastdate = $fields[9];
	 $lastdate =~ m/(.*)\s.*/;
	 $lastdate = $1;
     next if ($status eq "suspended");
	 if (! ispmf ($id))
	 {
	   $generic{$id} = $lastdate if ($role eq "user");
	   next;
	 }
	 if (isexception($id))
	 {
	   $exceptions{$id} = $lastdate;
	   next;
	 }
	 $candidates{$id}{$email} = $lastdate if ($role eq "user");
	 push @admins, $email if ($role eq "admin");
  }
}

sub ghedelete {
  my @users = @_;
  my $rcm = "ghe-user-suspend";
  my $ssh2 = Net::SSH2->new();
  my $chan;
  $ssh2->connect("$gheserver", 122) or die $!;
  if ($ssh2->auth_publickey('admin', "$pubkey", "$key")) 
  {
#      $chan = $ssh2->channel();
	  foreach my $user (@users)
	  {
	  	$user =~ s/\$/-/g;
		$chan = $ssh2->channel(); # ouch SSH2!
		print "ghe delete $user ...\n";
		$chan->exec("$rcm $user");
		$chan->close;
      }
#	  $chan->close;
      $ssh2->disconnect;
  }
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
      printv ("$searchString is not a valid domain user\n");
   }
   elsif ($mesg->count > 1)  {
     printv ("$searchString is not unique\n");
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
#   my $base = "dc=ca,dc=com"; 
   my $base = "cn=$searchString,ou=groups,OU=North America,dc=ca,dc=com";  # Better performance ...
   $mesg = $ldap->search ( base    => "$base",
                           filter  => "(&(objectClass=group))"
                         );
   $mesg->code && die $mesg->error;
#   printv ("Gropu search count = " . $mesg->count . "\n");
   if ($mesg->count == 0)  {
      printv ("$searchString is not a valid DL\n");
   }
   elsif ($mesg->count > 1)  {
     printv ("$searchString is not unique\n");
   }
   else {
     my $entry = $mesg->entry(0);
	 $groupdn = $entry->dn;
   }
   return $groupdn;
}

sub ldapdelete {
  my (@pmfs) = @_;
  my ($userdn, $groupdn);
  $ldap = Net::LDAP->new ( "usildc04.ca.com" ) or die "$@";
#  the best is to query the ldap user first. 
#  $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=ITC Hyderabad,dc=ca,dc=com", password => "$ldappw");
  $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=north america,dc=ca,dc=com", password => "$ldappw");
  $groupdn = LDAPGroupSearch ("$dl");  
  foreach my $pmf (@pmfs)
  {
    $userdn = LDAPSearch ("$pmf");
	print "ldap delete $userdn ...\n";
    if ($userdn && $groupdn)
    {
	 $mesg = $ldap->modify ($groupdn,
		  delete => {member => "$userdn" }
		  );
     $mesg->code && print $mesg->error;
    }
  }
  $ldap->unbind;
}

sub processWarn {
  my $cutoff = getpastdate($warning);
  my @emails;
  my $from = "GitHubAdmins\@ca.com";
  my $count = 0;
  foreach my $gen ( sort keys %generic)
  {
    if ($generic{$gen} lt $cutoff)
	{
	  printv("Account $gen $generic{$gen} - skipped as generic account");
	  printlog("Account $gen $generic{$gen} - skipped as generic account");
	}
  }
  foreach my $ex ( sort keys %exceptions)
  {
    if ($exceptions{$ex} lt $cutoff)
	{
	  printv("Account $ex $exceptions{$ex} - skipped as exception account");
	  printlog("Account $ex $exceptions{$ex} - skipped as exception account");
	}
  }
  foreach my $id ( sort keys %candidates )
 {
   foreach my $email (keys %{ $candidates{$id} })
   {
     if ($candidates{$id}{$email} lt $cutoff)
	 {
	   printv("Account $id $candidates{$id}{$email}");
	   printlog("Account $id $candidates{$id}{$email}");
	   push @emails, $email; 
	   $count += 1;
	 }
   }
 }
 if ($count)
 {
  if (! $opt_u)
  {  
   my $from = "GitHubAdmins\@ca.com";
   my $to = join ", ", @emails;
   printlog ("\nWarning users inactive $warning days ...");  
   printlog ("$count users are warned:");
   printv ("\n$count users are warned:");
   my $smtp = Net::SMTP->new('mail.ca.com', Debug=>0);
   $smtp->mail("$from");
#   $smtp->bcc ($to, {Notify => ['NEVER'], SkipBad => 1});
   $smtp->bcc ('gaoyu01@ca.com', {Notify => ['NEVER'], SkipBad => 1});
   $smtp->data();
   $smtp->datasend("Subject: Your GitHub Account Has Been Inacitve for $warning Days\n");
   $smtp->datasend("To: GHE Inactive Accounts");
   $smtp->datasend("\n");
   $smtp->datasend("\n");
   $smtp->datasend("Dear GitHub Enterprise User, \n\nThis is an informational message about your GitHub Enterprise account. Your account for http:\/\/$gheserver has been inactive for $warning days and will be suspended after $idle days of inactivity. \nNote a suspended account will retain the configuration settings in the GitHub application but will lose application access. \nOnce your account is suspended, you will need to reactivate it in order to obtain access again. \nThe instruction to reactivate a suspended GitHub account will be attached attached in the suspension email notification to the corresponding suspended account owner.\n\nRegards,\nTools Services Team\n\n- Browse https://tools.ca.com for more tools related information\n- Create Service Desk ticket at http://servicedesk.ca.com if you have any questions or concerns\n");
   $smtp->dataend();
   $smtp->quit();
   foreach (@emails)
   {
     printlog("Account $_ has been warned for inactivity for 60 days - " . printtime());
	 printv("Account $_ has been warned for inactivity for 60 days - " . printtime());
   }
  }
  else 
  {
    print "\n$count users are inactive for $warning days\n";
  }
 }
 else
 {
  if (! $opt_u)
  {  
    printlog ("\nNo user is at $warning days inactive.\n");
    printv ("\nNo user is at $warning days inactive.\n");
  }
  else 
  {
   print "No user is at $warning days inactive.\n";
  }
 }
}

sub processSuspend {
  my $cutoff = getpastdate($idle);
  my (@emails, @ids, $to);
  my $from = "GitHubAdmins\@ca.com";
  my $count = 0;
  my $smtp = Net::SMTP->new('mail.ca.com', Debug=>0);
  foreach my $id ( sort keys %candidates )
 {
   foreach my $email (keys %{ $candidates{$id} })
   {
     if ($candidates{$id}{$email} lt $cutoff)
	 {
	    push @emails, $email; 
	    push @ids, $id;
	    $count += 1;
	  }
    }
  }
 if ($count)
 {
  if (! $opt_u)
  {     
   printlog ("Suspending users inactive more than $idle days ...\n");  
   printlog ("$count users in process to suspend:");
   printv ("$count users in process to suspend:\n");
   ldapdelete(@ids); 
   ghedelete(@ids); # only needed to reactivate user immediately after being suspended
   foreach my $id (@ids)
   {
#     $to = "$id\@ca.com";
     $to = "gaoyu01\@ca.com";
	 my $subject = "Your GitHub Account Has Been Suspended"; 
     my $content = "Dear GitHub Enterprise User, <br><br>Your GitHub Enterprise account $id in http:\/\/$gheserver has been inactive for $idle or more days. It is suspended to release a corresponding seat license occupied. <br>A suspended account will retain the configuration settings in the GitHub application but will lose application access. <p>If you need to obtain access again, please click the link below.<br><br><a href=http://gheadmin.ca.com:8080/ghe/reactivate.jsp?name=$id&server=$gheserver>Reactivate My GitHub Account</a><br><br>Regards,<br>Tools Services Team<p>- Browse https://tools.ca.com for more tools related information<br>- Create Service Desk ticket at http://servicedesk.ca.com if you have any questions or concerns";
	 printv ("Account $id has been suspended for inactivity for $idle days - " . printtime());
	 printlog ("Account $id has been suspended for inactivity for $idle days - " . printtime());
	 my $msg = MIME::Lite->new(  
	    From     => $from,  
        To       => $to,  
        Subject  => $subject,  
        Type =>'text/html',
		Data     => $content			
        );  
	 $msg->send('smtp', 'mail.ca.com', Timeout=>60);
   }
   printv ("Informing GitHub administratros about suspended accounts...");
#   $to = join ", ", @admins;
   $to = "Team-GIS-ToolsSolutions-Global\@ca.com, Team-Tools-Deployment\@ca.com";
   $smtp->mail("$from");
   $smtp->to('gaoyu01@ca.com');
#   $smtp->to($to,{Notify => ['NEVER'], SkipBad => 1} );
   $smtp->data();
   $smtp->datasend("MIME-Version: 1.0\nContent-Type: text/html; charset=UTF-8 \n");
   $smtp->datasend("Subject: GitHub Accounts Suspended\n");
   $smtp->datasend("To: GitHub Enterprise Admins");
   $smtp->datasend("\n");
   $smtp->datasend("\n");
   $smtp->datasend("Dear GitHub Administrator, <br><br><b>GitHub Enterprise License Usage</b><br><table><tr><td>Server:</td><td>$gheserver</td></tr>$htmlusage<\/table><br>This is to inform you that the following $count GitHub user accounts that are inactive for $idle or more days are suspended. <br>" . join("<br>", @ids) . "<br>The counts of the GitHub Enterprise server license seats should be updated in less than 1 hour. <br><br>Regards,<br>Tools Services Team");
   $smtp->dataend();
   printlog("Email is sent to the following administrators:\n" . $to);
   printv("Email is sent to the following administrators:\n" . $to);
  }
  else
  {
    print "$count users are inactive for $idle or more days. \n";
  }
 }
 else
 {
  if (! $opt_u)
  {
   printlog ("\nNo accounts that are inactive for $idle or more days to suspend.");   
   printv ("\nNo accounts that are inactive for $idle or more days to suspend.");   
#   $to = join ", ", @admins;
    $to = "Team-GIS-ToolsSolutions-Global\@ca.com, Team-Tools-Deployment\@ca.com";
   $smtp->mail("$from");
   $smtp->to('gaoyu01@ca.com');
#   $smtp->to($to, {Notify => ['NEVER'], SkipBad => 1} );
#   $smtp->cc('Team-Tools-ArchitectCoreTeam@ca.com');
   $smtp->data();  
   $smtp->datasend("MIME-Version: 1.0\nContent-Type: text/html; charset=UTF-8 \n");
   $smtp->datasend("Subject: No GitHub Accounts To Suspend\n");
   $smtp->datasend("To: GitHub Enterprise Admins");   
   $smtp->datasend("\n");
   $smtp->datasend("\n");
   $smtp->datasend("Dear GitHub Enterprise Administrator, <br><br>The existing available GitHub Enterprise license count is below $threshold in server, $gheserver.<br>This is to inform you that there is no GitHub user account that is inactive for $idle or more days to suspend at this time.<br><br><b>GitHub Enterprise License Usage</b><br><table><tr><td>Server:</td><td>$gheserver</td></tr>$htmlusage<\/table><br><br>Regards,<br>Tools Services Team");
   $smtp->dataend();
   printlog ("GitHub Server, $gheserver, administrators have been notified.\n" . $to);   
   printv ("GitHub Server, $gheserver, administrators have been notified.\n" . $to);   
  }
  else 
  {
   print "No accounts that are inactive for $idle or more days to suspend.\n";
  }
 }
  $smtp->quit();
}

#future enhancement
sub APIDormantUsers {
}

sub APISuspendedUsers {
}

## main starts here
$opt_h && printusage();

$logfile = "GHELP_" . getdate() . ".log";
open (LOG, ">>$logfile") or die $!;
printlog("Starting new job on " . printtime());
printlog("GitHub Server: $gheserver");
if ((!$opt_v) && (! $opt_u))
{
  open STDERR, ">&LOG";
  select LOG;
}

$json = curlrun($APILicenseUsage);
$usage= "============ GitHub Enterprise License Usage ============\n" . 
	sprintf("%-25s %-30s\n", "Entitlement Type:", $json->{'kind'}) .
	sprintf("%-25s %-30s\n", "Total Entitled Seats:", $json->{'seats'}) .
	sprintf("%-25s %-30s\n", "Seats Used:", $json->{'seats_used'}) .
	sprintf("%-25s %-30s\n", "Seats Available:", $json->{'seats_available'}) .
	sprintf("%-25s %-30s\n", "Expiration Date:", $json->{'expire_at'}) .
	sprintf("%-25s %-30s\n", "Days Until Expiration:", $json->{'days_until_expiration'});
$htmlusage = "<tr><td>Entitlement Type:</td><td>$json->{'kind'}</td></tr>" . 
	"<tr><td>Total Entitled Seats:</td><td>$json->{'seats'}</td></tr>" . 
	"<tr><td>Seats Used:</td><td>$json->{'seats_used'}</td></tr>" . 
	"<tr><td>Seats Available:</td><td>$json->{'seats_available'}</td></tr>" . 
	"<tr><td>Expiration Date:</td><td>$json->{'expire_at'}</td></tr>" . 
	"<tr><td>Days Until Expiration:</td><td>$json->{'days_until_expiration'}</td></tr>";
	
printlog ("$usage");
printv ("$usage");
print "$usage" if ($opt_u);

printlog (sprintf ("%-35s %-15s", "Available License Threshold:", "$threshold seats"));
printlog (sprintf ("%-35s %-15s", "Warning Threshold:", "$warning days"));
printlog (sprintf ("%-35s %-15s\n", "Suspension Threshold:", "$idle days"));
printv (sprintf ("%-35s %-15s", "Available License Threshold:", "$threshold seats"));
printv (sprintf ("%-35s %-15s", "Warning Threshold:", "$warning days"));
printv (sprintf ("%-35s %-15s\n", "Suspension Threshold:", "$idle days"));

QueryDormantUsers();
processWarn();

if (($json->{'seats_available'} <= $threshold && (! $opt_wo)) || $opt_u)
{
  processSuspend ();
}
elsif ((! $opt_wo))
{
  printlog ("\nEnough seats available and no need to suspend any account!");
  printv ("\nEnough seats available and no need to suspend any account!");
}
close LOG;
printv("\nExisting ...\n");
exit 0;






