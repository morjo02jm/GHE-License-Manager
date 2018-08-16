#!/usr/bin/perl

############################################################################
# the script executes suspending use part of the GHE license sharing policy. 
# Grace Gao - 5/3/2016 
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
use Config::Simple;
use Crypt::CBC;
use Crypt::Blowfish;
use MIME::Base64;

open STDERR, ">&STDOUT";
select STDERR; $| = 1;
select STDOUT; $| = 1;

use vars qw($opt_h $opt_v $opt_s $opt_t $opt_n $opt_w $opt_d $opt_webserver $opt_e $opt_wo $opt_u $opt_key $opt_pubkey $opt_rs $opt_cp $opt_gheusr $opt_ghepw $opt_ldapusr $opt_ldappw $opt_ldapgroup);

GetOptions('h', 'v', 'wo', 'u', 's=s', 't=i', 'n=i', 'w=i', 'd=i', 'webserver=s', 'e=s', 'rs=s', 'key=s', 'pubkey=s', 'cp=s', 'gheusr=s', 'ghepw=s', 'ldapusr=s', 'ldasppw=s', 'ldapgroup=s') ||  printusage();
my $cfg = new Config::Simple('config.ini') || die ("config.ini file is not found\n");
my $verbose = $opt_v || $cfg->param('verbose');
my $webserver = $opt_webserver || $cfg->param('webserver');
my $gheserver = $opt_s || $cfg->param('gheserver');
my $threshold = $opt_t ||$cfg->param('threshold'); #total 2250 seats
my $notifythreshhold = $opt_n || $cfg->param('notifythreshhold'); 
my $idle = $opt_d || $cfg->param('idle');
my $warning = $opt_w || $cfg->param('warning');
my $exfile = $opt_e || $cfg->param('exfile');
my $gheusr = $opt_ldapusr || $cfg->param('gheusr');
my $ghepw = $opt_ldappw || $cfg->param('ghepw');
my $ldapusr = $opt_ldapusr || $cfg->param('ldapusr');
my $ldappw = $opt_ldappw || $cfg->param('ldappw');
my $dl = $opt_ldapgroup || $cfg->param('dl');
my $rscript = $opt_rs || $cfg->param('rscript');
my $cp = $opt_cp || $cfg->param('cp');
my $key = $opt_key || $cfg->param('key');
my $pubkey = $opt_pubkey || $cfg->param('pubkey');
my $gpath = $cfg->param('gpath');
my $sqlpath = $cfg->param('sqlpath');
my @newadmins = split(/\;/, $cfg->param('newadmins'));
# for autosys job 
my $home = $cfg->param('home');

my ($logfile, $usage, $htmlusage, $json, $freeseats, $ldap, $mesg, %candidates, %generic, %exceptions, @admins, @elist, @members);
my $enckey = "YesGoCA";
my $cipher = Crypt::CBC->new( -key    => $enckey,
                             -cipher => 'Blowfish',
                           );
$ghepw = decode_base64($ghepw);
$ghepw = $cipher->decrypt( $ghepw );
$ldappw = decode_base64($ldappw);
$ldappw = $cipher->decrypt( $ldappw );

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
 $verbose && print("@_\n");
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
  return 1 if ($pmf =~ m/^.{5}\d{2}\s*$/);
  return 0;
}

sub isexception {
  my $pmf = shift;
  return 1 if (grep(/$pmf/i, @elist));
  return 0;
}

sub curlrun {
  my $url = shift;
  my $jcmd = "curl -s -u $gheusr:pw $url"; # hide pw
  my $jsondata = `curl -s -u $gheusr:\"$ghepw\" $url`; #GitHub tends to cache first
  printlog("Extracting current GHE license usage ...");
  printv("Extracting current GHE license usage ...\n");
  printv("Executing $jcmd\n");
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
  if ($cp)
  {
    $cmd = "$gpath\\scp -o 'StrictHostKeyChecking no' -i $key -P 122 $cp admin\@$gheserver:/tmp/";
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
  $fn =~ m/Saving list of users to \'$sqlpath\/(.+)\'\.\.\./;
  $fname = $1;
  $cmd = "$gpath\\scp -o 'StrictHostKeyChecking no' -i $key -P 122 admin\@$gheserver:/tmp/$fname ." if ($fname);
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

sub LDAPSearch {
   my ($searchString) = shift;
   $searchString = "*" . $searchString . "*";
   my $userdn;
   my $base = "dc=ca,dc=com"; 
   $mesg = $ldap->search ( base    => "$base",
                           filter  => "(&(!(objectclass=computer))(&(proxyAddresses=$searchString)(objectclass=person)))"
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

sub LDAPGroupSearch {
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

sub GetGroupMembers {
   my $group = shift;
   my $index = 0;
   my @members;
   my $attr;
   my $base = "cn=$group,ou=groups,OU=North America,dc=ca,dc=com"; 
   $ldap = Net::LDAP->new ( "usildc04.ca.com" ) or die "$@";
  $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=ITC Hyderabad,dc=ca,dc=com", password => "$ldappw");
   while ($index ne '*') {
   $mesg = $ldap->search ( base    => "$base",
                         filter  => "(&(objectClass=group))",
						 scope  => 'base',
                         attrs  => [ ($index > 0) ? "member;range=$index-*" : 'member' ]
                         );
                         
  $mesg->code && die $mesg->error;
  
   if ($mesg->count == 0)  {
      print "$group is not a valid DL!\n";
   }
   elsif ($mesg->count > 1)  {
     print "$group is not unique!\n";
   }
   else {
     my $entry = $mesg->entry(0);
	 # range option
     if (($attr) = grep(/^member;range=/, $entry->attributes)) {
        push(@members, $entry->get_value($attr));
        if ($attr =~ /^member;range=\d+-(.*)$/) {
          $index = $1;
          $index++  if ($index ne '*');
        }
      }
	   # small group
      else {
        @members = $entry->get_value('member');
        last;
      }
     }
   } 
   $mesg = $ldap->unbind; 
   return @members;
}

sub ldapdelete {
  my (@pmfs) = @_;
  my $userdn;
  my $groupdn;
  $ldap = Net::LDAP->new ( "usildc04.ca.com" ) or die "$@";
#  the best is to query the ldap user first. 
  $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=ITC Hyderabad,dc=ca,dc=com", password => "$ldappw");
#  $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=north america,dc=ca,dc=com", password => "$ldappw");
  $groupdn = LDAPGroupSearch ("$dl");  
  foreach my $pmf (@pmfs)
  {
    $userdn = LDAPSearch ("$pmf");
    if ($userdn && $groupdn)
    {
	 print "ldap delete $userdn ...\n";
	 $mesg = $ldap->modify ($groupdn,
		  delete => {member => "$userdn" }
		  );
     $mesg->code && print $mesg->error;
    }
  }
  $mesg = $ldap->unbind;
}

sub processWarn {
  my $cutoff = getpastdate($warning);
  my @emails;
  my $from = "ToolsSolutionsCommunications\@ca.com";
  my $count = 0;
  @members = GetGroupMembers($dl);
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
     if ($candidates{$id}{$email} eq $cutoff)
	 {
      if (grep(/\Q$id\E/i, @members))
	   {
	     printv("Account $id $candidates{$id}{$email}");
	     printlog("Account $id $candidates{$id}{$email}");
	     push @emails, $email; 
	     $count += 1;
	   }
	   else
	   {
	     printv("Account $id $candidates{$id}{$email} - skipped as a sub DL member");
	     printlog("Account $id $candidates{$id}{$email} - skipped as a sub DL member");
	   }
	  }
   }
 }
 if ($count)
 {
  if (! $opt_u)
  {  
#   my $from = "GitHubAdmins\@ca.com";
#   my $to = join ", ", @emails;
   printlog ("\nWarning users inactive $warning days ...");  
   printlog ("$count users are warned:");
   printv ("\n$count users are warned:");
   my $smtp = Net::SMTP->new('mail.ca.com', Debug=>0);
   $smtp->mail("$from");
   $smtp->bcc (@emails, {Notify => ['NEVER'], SkipBad => 1});
#   $smtp->bcc ('gaoyu01@ca.com', {Notify => ['NEVER'], SkipBad => 1});
   $smtp->data();
   $smtp->datasend("Subject: Your GitHub Enterprise account has been inactive for $warning days\n");
   $smtp->datasend("To: GHE Inactive Accounts");
   $smtp->datasend("\n");
   $smtp->datasend("\n");
   $smtp->datasend("Dear GitHub Enterprise user, \n\nThis is an informational message about your GitHub Enterprise account. Your account for https:\/\/$gheserver has been inactive for $warning days and will be suspended after $idle days of inactivity. \nThe suspended account will retain all settings and permissions, but not have access to login and use the application. \nOnce your account is suspended, you will need to unsuspend yourself in order to use the application again. \nUnsuspending yourself is very simple, and the procedure is mentioned in the mail notification you shall recieve if your account does get suspended.\n\nRegards,\nTools Services team\n");
   $smtp->dataend();
   $smtp->quit();
   foreach (@emails)
   {
     printlog("Account $_ has been warned for inactivity for 30 days - " . printtime());
	 printv("Account $_ has been warned for inactivity for 30 days - " . printtime());
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
  my (@emails, @ids, $to, $smtp);
  my $from = "ToolsSolutionsCommunications\@ca.com";
  my $count = 0;
  @members = GetGroupMembers($dl);
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
	  if (grep(/\Q$id\E/i, @members))
	   {
	     printv("Account $id $candidates{$id}{$email}");
	     printlog("Account $id $candidates{$id}{$email}");
	     push @emails, $email; 
	     push @ids, $id;
	     $count += 1;
	   }
	   else
	   {
	     printv("Account $id $candidates{$id}{$email} - skipped as a sub DL member");
	     printlog("Account $id $candidates{$id}{$email} - skipped as a sub DL member");
	   }
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
   $ldap = Net::LDAP->new ( "usildc04.ca.com" ) or die "$@";
   $mesg = $ldap->bind( "cn=$ldapusr,ou=Role-Based,ou=ITC Hyderabad,dc=ca,dc=com", password => "$ldappw") or die $!;
   foreach my $id (@ids)
   {
    if (LDAPSearch($id))
	{
     $to = "$id\@ca.com";
	 my $subject = "Your GitHub Enterprise account has been suspended"; 
     my $content = "Dear GitHub Enterprise user,<br><br>Your account $id in https:\/\/$gheserver has been inactive for $idle or more days. Your account has been suspended to avoid dormant users occupying a GitHub Enterprise license.<br>Note: Your suspended account will retain all settings and permissions, but will not have access to the application until your GHE access has been resinstated.<p>If you require access to GitHub again, you can unsuspend yourself easily using the link below.<br><a href="http://devtools.ca.com/github/unsuspend"><b>Unsuspend your account</b></a><br><br>Regards,<br>Tools Services Team</p>";
	 printv ("Account $id has been suspended for inactivity for $idle days - " . printtime());
	 printlog ("Account $id has been suspended for inactivity for $idle days - " . printtime());
	 my $msg = MIME::Lite->new(  
	    From     => $from,  
        To       => $to,  
        Subject  => $subject,  
        Type =>'text/html',
		Data     => $content			
        );  
	 $msg->send('smtp', 'mail.ca.com', Timeout=>60, Debug=>1);
    }
	else 
	{
	 printv ("$id has no email address!\n");
	}
   }
   $ldap->unbind;
   printv ("Informing GitHub Enterprise administrators about suspended accounts...");
   $smtp = Net::SMTP->new('mail.ca.com', Debug=>1);
   $smtp->mail("$from");
   $smtp->to(@newadmins,{Notify => ['NEVER'], SkipBad => 1} );
   $smtp->data();
   $smtp->datasend("MIME-Version: 1.0\nContent-Type: text/html; charset=UTF-8 \n");
   $smtp->datasend("Subject: GitHub Accounts Suspended\n");
   $smtp->datasend("To: GitHub Enterprise Admins");
   $smtp->datasend("\n");
   $smtp->datasend("\n");
   $smtp->datasend("Dear GitHub Enterprise administrator, <br><br><b>GitHub Enterprise license usage</b><br><table><tr><td>Server:</td><td>$gheserver</td></tr>$htmlusage<\/table><br>This is to inform you that the following $count GitHub Enterprise user accounts that were inactive for $idle or more days are suspended. <br>" . join("<br>", @ids) . "<br>The counts of the GitHub Enterprise server license seats should be updated in less than 1 hour. <br><br>Regards,<br>Tools Services team");
   $smtp->dataend();
   printlog("Email is sent to the following administrators:\n" . "@newadmins");
   printv("Email is sent to the following administrators:\n" . "@newadmins");
   $smtp->quit();
  }
  else
  {
    print "$count users are inactive for $idle or more days. \n@ids";
  }
 }
 else
 {
  if (! $opt_u)
  {
   printlog ("\nNo accounts that are inactive for $idle or more days to suspend.");   
   printv ("\nNo accounts that are inactive for $idle or more days to suspend.");   
   if ($freeseats < $notifythreshhold)
   {
   $smtp = Net::SMTP->new('mail.ca.com', Debug=>1);
   $smtp->mail("$from");
   $smtp->to(@newadmins, {Notify => ['NEVER'], SkipBad => 1} );
   $smtp->cc('Team-Tools-ArchitectCoreTeam@ca.com');
   $smtp->data();  
   $smtp->datasend("MIME-Version: 1.0\nContent-Type: text/html; charset=UTF-8 \n");
   $smtp->datasend("Subject: No GitHub Accounts To Suspend\n");
   $smtp->datasend("To: GitHub Enterprise Admins");   
   $smtp->datasend("\n");
   $smtp->datasend("\n");
   $smtp->datasend("Dear GitHub Enterprise administrator, <br><br>The current available GitHub license count is below $notifythreshhold in server, $gheserver.<br>This is to inform you that there is no GitHub user account that is inactive for $idle or more days to suspend at this time.<br><br><b>GitHub Enterprise License Usage</b><br><table><tr><td>Server:</td><td>$gheserver</td></tr>$htmlusage<\/table><br><br>Regards,<br>Tools Services team");
   $smtp->dataend();
   printlog ("GitHub Server, $gheserver, administrators have been notified.\n" . "@newadmins");   
   printv ("GitHub Server, $gheserver, administrators have been notified.\n" . "@newadmins");  
   $smtp->quit();   
   }
  }
  else 
  {
   print "No accounts that are inactive for $idle or more days to suspend.\n";
  }
 }
}

#future enhancement
sub APIDormantUsers {
}

sub APISuspendedUsers {
}

## main starts here
$opt_h && printusage();
chdir "$home" or die $!;
$logfile = "GHELP_" . getdate() . ".log";
open (LOG, ">>$logfile") or die $!;
printlog("Starting new job on " . printtime());
printlog("GitHub Server: $gheserver");
if ((!$verbose) && (! $opt_u))
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
$freeseats = $json->{'seats_available'};	
printlog ("$usage");
printv ("$usage");
print "$usage" if ($opt_u);

printlog (sprintf ("%-35s %-15s", "Available License Threshold:", "$threshold seats"));
printlog (sprintf ("%-35s %-15s", "Warning Threshold:", "$warning days"));
printlog (sprintf ("%-35s %-15s\n", "Suspension Threshold:", "$idle days"));
printv (sprintf ("%-35s %-15s", "Available License Threshold:", "$threshold seats"));
printv (sprintf ("%-35s %-15s", "Warning Threshold:", "$warning days"));
printv (sprintf ("%-35s %-15s\n", "Suspension Threshold:", "$idle days"));

open (EX, "<$exfile") or die $!;
@elist = <EX>;
close EX;


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






