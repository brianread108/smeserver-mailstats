#!/usr/bin/perl -w

#############################################################################
#
# This script provides daily SpamFilter statistics.
#
# This script was originally developed
# by Jesper Knudsen at http://sme.swerts-knudsen.dk 
# and re-written by brian read at bjsystems.co.uk (with some help from the community - thanks guys)
#
# bjr - 02sept12 - Add in qpsmtpd failure code auth::auth_cvm_unix_local as per Bug 7089
# bjr - 10Jun15  - Sort out multiple files as input parameters as per bug 5613
#                - Sort out geoip failure status as per Bug 4262
#		 						 - change final message about the DB (it is created automatically these days by the rpm)
# bjr - 17Jun15  - Add annotation showing Badcountries being eliminated
#								 - correct Spamfilter details extract, as per Bug 8656 
#                - Add analysis table of Geoip results 
# bjr - 19Jun15	 - Add totals for the League tables
# bjr and  Unnilennium  - 08Apr16 - Add in else for unrecognised plugin detection
# bjr - 08Apr16 - Add in link for SaneSecurity "extra" virus detection
# bjr - 14Jun16 - make compatible with qpsmtpd 0.96
# bjr - 16Jun16 - Add code to create an html equivalent of the text email (v0.7)
# bjr - 04Aug16 - Add code to log and count the blacklist RBL urls that have triggered, this (NFR) is Bugzilla 9717
# bjr - 04Aug16 - Add code to expand the junkmail table to include daily ham and spam and deleted spam for each user - (NFR bugzilla 9716)
# bjr - 05Aug16 - Add code to log remote relay incoming emails
# bjr - 10Oct16 - Add code to show stats for the smeoptimizer package
# bjr - 16dec16 - Fix dnsbl code to deal with psbl.surriel.com  - Bug 9717
# bjr - 16Dec16 - Change geopip table code to show even if no exclusions found (assuming geoip data found) - Bug 9888
# bjr - 30Apr17 - Change Categ index code - Bug 9888 again
# bjr - 18Dec19 - Sort out a few format problems and also remove some debugging crud - Bug 10858
# bjr - 18Dec19 - change to fix truncation of email address in by email table - bug 10327
#
#############################################################################
#
#  SMEServer DB usage
#  ------------------
#
#  mailstats / Status ("enabled"|"disabled")
#            / <column header> ("yes"|"no"|"auto") - enable, supress or only show if nonzero
#            / QpsmtpdCodes ("enabled"|"disabled")
#            / SARules ("enabled"|"disabled")
#            / GeoipTable  ("enabled"|"disabled")
#            / GeoipCutoffPercent (0.5%) - threshold to show Geoip country in league table
#            / JunkMailList  ("enabled"|"disabled")
#            / SARulePercentThreshold (0.5) - threshold of SArules percentage for report cutoff
#            / Email (admin) - email to send report
#            / SaveDataToMySQL  - save data to MySQL database (default is "no")
#						 / ShowLeagueTotals  - Show totals row after league tables - (default is "yes")
#            / DBHost - MySQL server hostname (default is "localhost").
#            / DBPort - MySQL server post (default is "3306")
#            / Interval - "daily", "weekly", "fortnightly", "monthly", "99999" - last is number of hours (default is daily)
#            / Base - "Midnight", "Midday", "Now", "99" hour (0-23) (default is midnight)
#						 / HTMLEmail - "yes", "no", "both" - default is "No" - Send email in HTML
#            NOT YET INUSE - WIP!
#						 / HTMLPage - "yes"  / "no"  - default is "yes" if HTMLEmail is "yes" or "both" otherwise "no"
#
#############################################################################
#
#
#  TODO
#
# 1. Delete loglines records from any previous run of same table
# 2. Add tracking LogId for each cont in the table
# 3. Use link directory file to generate h1 / h2 tags for title and section headings
# 4. Ditto for links to underlying data
#

# internal modules (part of core perl distribution)
use strict;
use warnings;
use Getopt::Long;
use Pod::Usage;
use POSIX qw/strftime floor/;
use Time::Local;
use Date::Parse;
use Time::TAI64;
use esmith::ConfigDB;
use esmith::DomainsDB;
use Sys::Hostname;
use Switch;
use DBIx::Simple;
use URI::URL;

#use CGI;
#use HTML::TextToHTML;

my $hostname = hostname();
my $cdb = esmith::ConfigDB->open_ro or die "Couldn't open ConfigDB : $!\n";

my $true = 1;
my $false = 0;
#and see if mailstats are disabled
my $disabled;
if ($cdb->get('mailstats')){
  $disabled = !(($cdb->get('mailstats')->prop('Status') || 'enabled') eq 'enabled');
} else {
  my $db = esmith::ConfigDB->open; my $record = $db->new_record('mailstats', { type => 'report', Status => 'enabled', Email => 'admin' });
  $cdb = esmith::ConfigDB->open_ro or die "Couldn't open ConfigDB : $!\n";  #Open up again to pick up new record
  $disabled = $false;
}

#Configuration section
my %opt = (
    version => '0.7.13',                        # please update at each change.
    debug => 0,                                 # guess what ?
    sendmail => '/usr/sbin/sendmail',           # Path to sendmail stub
    from => 'spamfilter-stats',                 # Who is the mail from
    mail => $cdb->get('mailstats')->prop('Email') || 'admin', # mailstats email recipient
    timezone => `date +%z`,
);

my $FetchmailIP = '127.0.0.200';       #Apparent Ip address of fetchmail deliveries
my $WebmailIP = '127.0.0.1';           #Apparent Ip of Webmail sender
my $localhost = 'localhost';           #Apparent sender for webmail
my $FETCHMAIL = 'FETCHMAIL';    #Sender from fetchmail when Ip address not 127.0.0.200 - when qpsmtpd denies the email
my $MAILMAN = "bounces";        #sender when mailman sending when orig is localhost
my $DMARCDomain="dmarc"; 				#Pattern to recognised DMARC sent emails (this not very reliable, as the email address could be anything)
my $DMARCOkPattern="dmarc: pass";  #Pattern to use to detect DMARC approval
my $localIPregexp = ".*((127\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.)).*";
my $MinCol = 6;                 #Minimum column width
my $HourColWidth = 16;            #Date and time column width

my $SARulethresholdPercent = 10;  #If Sa rules less than this of total emails, then cutoff reduced
my $maxcutoff = 1; #max percent cutoff applied
my $mincutoff = 0.2; #min percent cutoff applied

my $tstart = time;

#Local variables
my $YEAR = ( localtime(time) )[5];    # this is years since 1900

my $total         = 0;
my $spamcount     = 0;
my $spamavg       = 0;
my $spamhits      = 0;
my $hamcount      = 0;
my $hamavg        = 0;
my $hamhits       = 0;
my $rejectspamavg = 0;
my $rejectspamhits= 0;

my $Accepttotal      = 0;
my $localAccepttotal = 0;             #Fetchmail connections
my $localsendtotal   = 0;             #Connections from local PCs
my $totalexamined = 0;                #total download + RBL etc
my $WebMailsendtotal = 0;             #total from Webmail
my $mailmansendcount = 0;             #total from mailman
my $DMARCSendCount = 0;        		    #total DMARC reporting emails sent (approx)
my $DMARCOkCount = 0;                 #Total emails approved through DMARC



my %found_viruses = ();
my %found_qpcodes  = ();
my %found_SARules = ();
my %junkcount = ();
my %unrecog_plugin = ();
my %blacklistURL = ();  #Count of use of each balcklist rhsbl
my %usercounts = ();    #Count per received email of sucessful delivery, queued spam and deleted Spam, and rejected

# replaced by...
my %counts = ();                    #Hold all counts in 2-D matrix
my @display = ();                   #used to switch on and off columns  - yes, no or auto for each category
my @colwidth = ();                  #width of each column
                                    #(auto means only if non zero) - populated from possible db entries
my @finaldisplay = ();              #final decision on display or not  - true or false

#count column names, used for headings  - also used for DB mailstats property names
my $CATHOUR='Hour';
my $CATFETCHMAIL='Fetchmail';
my $CATWEBMAIL='WebMail';
my $CATMAILMAN='Mailman';
my $CATLOCAL='Local';
my $CATRELAY="Relay";
# border between where it came from and where it ended..
my $countfromhere = 6;  #Temp - Check this not moved!!
 
my $CATVIRUS='Virus';
my $CATRBLDNS='RBL/DNS';
my $CATEXECUT='Execut.';
my $CATNONCONF='Non.Conf.';
my $CATBADCOUNTRIES='Geoip.';
my $CATKARMA="Karma";

my $CATSPAMDEL='Del.Spam';
my $CATSPAM='Qued.Spam?';
my $CATHAM='Ham';
my $CATTOTALS='TOTALS';
my $CATPERCENT='PERCENT';
my $CATDMARC="DMARC Rej.";
my $CATLOAD="Rej.Load";
my @categs = ($CATHOUR,$CATFETCHMAIL,$CATWEBMAIL,$CATMAILMAN,$CATLOCAL,$CATRELAY,$CATDMARC,$CATVIRUS,$CATRBLDNS,$CATEXECUT,$CATBADCOUNTRIES,$CATNONCONF,$CATLOAD,$CATKARMA,$CATSPAMDEL,$CATSPAM,$CATHAM,$CATTOTALS,$CATPERCENT);
my $GRANDTOTAL = '99';                #subs for count arrays, for grand total
my $PERCENT = '98';                 # for column percentages

my $categlen = @categs-2;  #-2 to avoid the total and percent column

#
# Index for certain columns - check these do not move if we add columns
#
#my $BadCountryCateg=9;     
#my $DMARCcateg = 5;  #Not used.
#my $KarmaCateg=$BadCountryCateg+3;

my %categindex;
@categindex{@categs} = (0..$#categs);
my $BadCountryCateg=$categindex{$CATBADCOUNTRIES};
my $DMARCcateg = $categindex{$CATDMARC};  #Not used.
my $KarmaCateg=$categindex{$CATKARMA};

my $above15 = 0;
my $RBLcount  = 0;
my $MiscDenyCount = 0;
my $PatternFilterCount  = 0;
my $noninfectedcount = 0;
my $okemailcount     = 0;
my $infectedcount  = 0;
my $warnnoreject = " ";
my $rblnotset    = ' ';

my %found_countries = ();
my $total_countries = 0;
my $BadCountries = "";     #From the DB

my $FS = "\t";    # field separator used by logterse plugin
my %log_items = ( "", "", "", "", "", "", "", "" );
my $score;
my %timestamp_items = ();
my $localflag = 0;        #indicate if current email is local or not
my $WebMailflag = 0;      #indicate if current mail is send from webmail

# some storage for by recipient domains stats (PS)
# my bad : I have to deal with multiple simoultaneous connections
# will play with the process number.
# my $currentrcptdomain = '' ;
my %currentrcptdomain ;      # temporay store the recipient domain until end of mail processing
my %byrcptdomain ;           # Store 'by domains stats'
my @extdomain ;              # only useful in some MX-Backup case, when any subdomains are allowed
my $morethanonercpt = 0 ;    # count every 'second' recipients for a mail.
my $recipcount = 0;    	     # count every recipient email address received.

#
#Load up the emails curreently stored for DMARC reporting - so that we cna spot the reports being sent.
#Held in an slqite db, created by the DMARC perl lib.
#
my $dsn = "dbi:SQLite:dbname=/var/lib/qpsmtpd/dmarc/reports.sqlite"; #Taken from /etc/mail-dmarc.ini
# doesn't seem to need 
my $user = "";
my $pass = "";
my $DMARC_Report_emails = ""; #Flat string of all email addresses

 if (my $dbix = DBIx::Simple->connect( $dsn, $user, $pass )){
	 my $result = $dbix->query("select rua from report_policy_published;");
	 $result->bind(my ($emailaddress));
	 while ($result->fetch){
			#remember email from logterse entry has chevrons round it - so we add them here to guarantee the alighment of the match
			#Remove the mailto:
			$emailaddress =~ s/mailto://g;
			# and map any commas to ><
			$emailaddress =~ s/,/></g;			
			$DMARC_Report_emails .= "<".$emailaddress.">\n"
	 }
	 $dbix->disconnect();
	} else { $DMARC_Report_emails = "None found - DB not opened"}



# and setup list of local domains for spotting the local one in a list of email addresses (Remote station processing)
use esmith::DomainsDB;
my $d = esmith::DomainsDB->open_ro();
my @domains = $d->keys();
my $alldomains = "(";
foreach my $dom (@domains){$alldomains .= $dom."|"}
$alldomains .= ")";

# Saving the Log lines processed
my %LogLines = ();  #Save all the log lines processed for writing to the DB
my %LogId = ();     #Save the Log Ids.
my $CurrentLogId = ""; 
my $Sequence = 0;


# store the domain of interest. Every other records are stored in a 'Other' zone
my $ddb = esmith::DomainsDB->open_ro or die "Couldn't open DomainsDB : $!\n";

foreach my $domain( $ddb->get_all_by_prop( type => "domain" ) ) {
    $byrcptdomain{ $domain->key }{ 'type' }='local';
}
$byrcptdomain{ $cdb->get('SystemName')->value . "."
               . $cdb->get('DomainName')->value }{ 'type' } = 'local';

# is this system a MX-Backup ?
if ($cdb->get('mxbackup')){
  if ( ( $cdb->get('mxbackup')->prop('status') || 'disabled' ) eq 'enabled' ) {
      my %MXValues = split( /,/, ( $cdb->get('mxbackup')->prop('name') || '' ) ) ;
      foreach my $data ( keys %MXValues ) {
      $byrcptdomain{ $data }{ 'type' } = "mxbackup-$MXValues{ $data }" ;
           if ( $MXValues{ $data } == 1 ) { # subdomains allowed, must take care of this
               push @extdomain, $data ;
           }
       }
  }
}

my ( $start, $end ) = analysis_period();


#
# First check current configuration for logging, DNS enable and Max threshold for spamassassin
#

my $LogLevel    = $cdb->get('qpsmtpd')->prop('LogLevel');
my $HighLogLevel = ( $LogLevel > 6 );

my $RHSenabled =
  ( $cdb->get('qpsmtpd')->prop('RHSBL') eq 'enabled' );
my $DNSenabled =
  ( $cdb->get('qpsmtpd')->prop('DNSBL') eq 'enabled' );
my $SARejectLevel =
  $cdb->get('spamassassin')->prop('RejectLevel');
my $SATagLevel =
  $cdb->get('spamassassin')->prop('TagLevel');
my $DomainName =
  $cdb->get('DomainName')->value;

# check that logterse is in use
#my pluginfile = '/var/service/qpsmtpd/config/peers/0';

if ( !$RHSenabled || !$DNSenabled ) {
    $rblnotset = '*';
}

if ( $SARejectLevel == 0 ) {

    $warnnoreject = "(*Warning* 0 = no reject)";

}

# get enable/disable subsections
my $enableqpsmtpdcodes;
my $enableSARules;
my $enableGeoiptable;
my $enablejunkMailList;
my $savedata;
my $enableblacklist;  #Enabled according to setting in qpsmtpd
if ($cdb->get('mailstats')){
		$enableqpsmtpdcodes = ($cdb->get('mailstats')->prop("QpsmtpdCodes") || "enabled") eq "enabled" || $false;
		$enableSARules = ($cdb->get('mailstats')->prop("SARules") || "enabled") eq "enabled" || $false;
		$enablejunkMailList = ($cdb->get('mailstats')->prop("JunkMailList") || "enabled") eq "enabled" || $false;
		$enableGeoiptable = ($cdb->get('mailstats')->prop("Geoiptable") || "enabled") eq "enabled" || $false;
		$savedata = ($cdb->get('mailstats')->prop("SaveDataToMySQL") || "no") eq "yes" || $false;
	} else {
		$enableqpsmtpdcodes = $true;
		$enableSARules = $true;
		$enablejunkMailList = $true;
		$enableGeoiptable = $true;
		$savedata = $false;
	}
	$enableblacklist = ($cdb->get('qpsmtpd')->prop("RHSBL") || "disabled") eq "enabled" || ($cdb->get('qpsmtpd')->prop("URIBL") || "disabled") eq "enabled";

my $makeHTMLemail = "no";
#if ($cdb->get('mailstats')){$makeHTMLemail = $cdb->get('mailstats')->prop('HTMLEmail') || "no"} #TEMP!!
my $makeHTMLpage = "no";
#if ($makeHTMLemail eq "yes" || $makeHTMLemail eq "both") {$makeHTMLpage = "yes"}
#if ($cdb->get('mailstats')){$makeHTMLpage = $cdb->get('mailstats')->prop('HTMLPage') || "no"}


# Init the hashes
my $nhour = floor( $start / 3600 );
my $ncateg;
while ( $nhour < $end / 3600 ) {
      $counts{$nhour}=();
    $ncateg = 0;
    while ( $ncateg < @categs) {
      $counts{$nhour}{$categs[$ncateg-1]} = 0;
      $ncateg++
    }
    $nhour++;
}
# and grand totals, percent and display status from db entries, and column widths
$ncateg = 0;
my $colpadding = 0;
while ( $ncateg < @categs) {
  $counts{$GRANDTOTAL}{$categs[$ncateg]} = 0;
  $counts{$PERCENT}{$categs[$ncateg]} = 0;

  if ($cdb->get('mailstats')){
    $display[$ncateg] = lc($cdb->get('mailstats')->prop($categs[$ncateg])) || "auto";
  } else {
    $display[$ncateg] = 'auto'
  }
  if ($ncateg == 0) {
    $colwidth[$ncateg] = $HourColWidth + $colpadding;
  } else {
    $colwidth[$ncateg] = length($categs[$ncateg])+1+$colpadding;
  }
  if ($colwidth[$ncateg] < $MinCol) {$colwidth[$ncateg] = $MinCol + $colpadding}
  $ncateg++
}

my $starttai = Time::TAI64::unixtai64n($start);
my $endtai = Time::TAI64::unixtai64n($end);
my $sum_SARules = 0;

# we remove non valid files
my @ARGV2;
foreach ( map { glob } @ARGV){
  push(@ARGV2,($_));
}
@ARGV=@ARGV2;

my $count = -1; #for loop reduction in debugging mode

#
#---------------------------------------
# Scan the qpsmtpd log file(s)
#---------------------------------------


my $CurrentMailId = "";

LINE: while (<>) {

    next LINE if !(my($tai,$log) = split(' ',$_,2));

    
    #If date specified, only process lines matching date
    next LINE if ( $tai lt $starttai );
    next LINE if ( $tai gt $endtai );

		#Count lines and skip out if debugging
		$count++;
		#last LINE if ($opt{debug} && $count >= 100);
			

		#Loglines to Saved String for later DB write
		if ($savedata) {
			my $CurrentLine = $_;
			$CurrentLine = /^\@([0-9a-z]*) ([0-9]*) .*$/;
			my $l = length($CurrentLine);
			if ($l != 0){
				if (defined($2)){	
					if ($2 ne $CurrentMailId) {
						print "CL:$CurrentLine*\n" if !defined($1);
						$CurrentLogId = $1."-".$2;
						$CurrentMailId = $2;
						$Sequence = 0;
					} else {$Sequence++}
					#$CurrentLogId .=":".$Sequence;
					$LogLines{$CurrentLogId.":".$Sequence} = $_;
				}
			}
		}


    # pull out spamasassin rule lists
    if ( $_ =~m/spamassassin: pass, Ham,(.*)</ )
    #if ( $_ =~m/spamassassin plugin.*: check_spam:.*hits=(.*), required.*tests=(.*)/ )
    {
		 #New version does not seem to have spammassasin tests in logs 
		 #if (exists($2){  
			 #my (@SAtests) = split(',',$2);
			 #foreach my $SAtest (@SAtests) {
				 #if (!$SAtest eq "") {
					 #$found_SARules{$SAtest}{'count'}++;
					 #$found_SARules{$SAtest}{'totalhits'} += $1;
					 #$sum_SARules++
				 #}
			 #}
			#}
			
    }
    
    
    #Pull out Geoip countries for analysis table
    if ( $_ =~m/check_badcountries: GeoIP Country: (.*)/ )
    {
     $found_countries{$1}++;
     $total_countries++;
    }
    
    #Pull out DMARC approvals
    if ( $_ =~m/.*$DMARCOkPattern.*/ )
    {
			$DMARCOkCount++;
    }
    

    #only select Logterse output
    next LINE unless m/logging::logterse:/;

    my $abstime = Time::TAI64::tai2unix($tai);
    my $abshour = floor( $abstime / 3600 );    # Hours since the epoch


    my ($timestamp_part, $log_part) = split('`',$_,2);  #bjr 0.6.12
    my (@log_items) = split $FS, $log_part;

    my (@timestamp_items) = split(' ',$timestamp_part);
    
		my $result= "rejected";  #Tag as rejected unti we know otherwise
    # we store the more recent recipient domain, for domain statistics
    # in fact, we only store the first recipient. Could be sort of headhache
    # to obtain precise stats with many recipients on more than one domain !
    my $proc = $timestamp_items[1] ;  #numeric Id for the email
    my $emailnum = $proc; #proc gets modified later...

    if ($emailnum == 23244) {
		}
		
    $totalexamined++;

		
    # first spot the fetchmail and local deliveries.

    # Spot from local workstation
    $localflag   = 0;
    $WebMailflag = 0;
    if ( $log_items[1] =~ m/$DomainName/ ) {  #bjr
        $localsendtotal++;
        $counts{$abshour}{$CATLOCAL}++;
        $localflag = 1;
    }
    
    #Or a remote station    
    elsif ((!test_for_private_ip($log_items[0])) and (test_for_private_ip($log_items[2])) and ($log_items[5] eq "queued"))
    {
			#Remote user
			$localflag = 1;
			$counts{$abshour}{$CATRELAY}++;
		}

		elsif (($log_items[2] =~ m/$WebmailIP/) and (!test_for_private_ip($log_items[0]))) {
			#Webmail
			$localflag = 1;
			$WebMailsendtotal++;
			$counts{$abshour}{$CATWEBMAIL}++;
			$WebMailflag = 1;
		}

    # see if from localhost
    elsif ( $log_items[1] =~ m/$localhost/ ) {
        # but not if it comes from fetchmail
        if ( $log_items[3] =~ m/$FETCHMAIL/ ) { }
        else {
						$localflag = 1;
            # might still be from mailman here
            if ( $log_items[3] =~ m/$MAILMAN/ ) {
                $mailmansendcount++;
                $localsendtotal++;
                $counts{$abshour}{$CATMAILMAN}++;
                $localflag = 1;
            }
            else {
								#Or sent to the DMARC server
								#check for email address in $DMARC_Report_emails string
								my $logemail = $log_items[4];
								if ((index($DMARC_Report_emails,$logemail)>=0) or ($logemail =~ m/$DMARCDomain/)){
									$localsendtotal++;
									$DMARCSendCount++;
									$localflag = 1;
								}
								else {
									if (exists $log_items[8]){
										# ignore incoming localhost spoofs
										if ( $log_items[8] =~ m/msg denied before queued/ ) { }
										else {
												#Webmail
												$localflag = 1;
												$WebMailsendtotal++;
												$counts{$abshour}{$CATWEBMAIL}++;
												$WebMailflag = 1;
										}
									}	
									else {
										$localflag = 1;
										$WebMailsendtotal++;
										$counts{$abshour}{$CATWEBMAIL}++;
										$WebMailflag = 1;
									}
								}
            }
        }
    }

    # try to spot fetchmail emails
    if ( $log_items[0] =~ m/$FetchmailIP/ ) {
        $localAccepttotal++;
        $counts{$abshour}{$CATFETCHMAIL}++;
    }
    elsif ( $log_items[3] =~ m/$FETCHMAIL/ ) {
        $localAccepttotal++;
        $counts{$abshour}{$CATFETCHMAIL}++;
    }

# and adjust for recipient field if not set-up by denying plugin - extract from deny msg

    if ( length( $log_items[4] ) == 0 ) {
        if ( $log_items[5] eq 'check_goodrcptto' ) {
            if ( $log_items[7] gt "invalid recipient" ) {
                $log_items[4] =
                  substr( $log_items[7], 16 );    #Leave only email address

            }
        }
    }

    #        if ( ( $currentrcptdomain{ $proc } || '' ) eq '' ) {
    # reduce to lc and process each e,mail if a list, pseperatedy commas
    my $recipientmail = lc( $log_items[4] );
    if ( $recipientmail =~ m/.*,/ ) {

        #comma - split the line and deal with each domain
        #              print $recipientmail."\n";
        my ($recipients) = split( ',', $recipientmail );
        foreach my $recip ($recipients) {
            $proc = $proc . $recip;

            #            print $proc."\n";
            $currentrcptdomain{$proc} = $recip;
            add_in_domain($proc);
            $recipcount++;
        }

        #         print "*\n";
        #count emails with more than one recipient
        #              $recipientmail =~ m/(.*),/;
        #              $currentrcptdomain{ $proc } = $1;
    }
    else {
        $proc = $proc . $recipientmail;
        $currentrcptdomain{$proc} = $recipientmail;
        add_in_domain($proc);
        $recipcount++;
    }

    #        } else {
    #            # there more than a recipient for a mail, how many daily ?
    #            $morethanonercpt++;
    #        }


   # then categorise the result


	if (exists $log_items[5]) {

		if ($log_items[5] eq 'naughty') {
			my $rejreason = $log_items[7];
			$rejreason = /.*(\(.*\)).*/;
			if (!defined($1)){$rejreason = "unknown"}
			else {$rejreason = $1}
			$found_qpcodes{$log_items[5]."-".$rejreason}++}
		else {$found_qpcodes{$log_items[5]}++}  ##Count different qpsmtpd result codes

		if ($log_items[5] eq 'check_earlytalker') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_relay') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_norelay') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'require_resolvable_fromhost') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_basicheaders') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'rhsbl') { $RBLcount++;$counts{$abshour}{$CATRBLDNS}++;mark_domain_rejected($proc);$blacklistURL{get_domain($log_items[7])}++}

		elsif ($log_items[5] eq 'dnsbl') { $RBLcount++;$counts{$abshour}{$CATRBLDNS}++;mark_domain_rejected($proc);$blacklistURL{get_domain($log_items[7])}++}

		elsif ($log_items[5] eq 'check_badmailfrom') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_badrcptto_patterns') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_badrcptto') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_spamhelo') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_goodrcptto extn') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'rcpt_ok') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'pattern_filter') { $PatternFilterCount++;$counts{$abshour}{$CATEXECUT}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'virus::pattern_filter') { $PatternFilterCount++;$counts{$abshour}{$CATEXECUT}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_goodrcptto') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_smtp_forward') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'count_unrecognized_commands') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_badcountries') {$MiscDenyCount++;$counts{$abshour}{$CATBADCOUNTRIES}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'tnef2mime') { } #Not expecting this one.

		elsif ($log_items[5] eq 'spamassassin') { $above15++;$counts{$abshour}{$CATSPAMDEL}++;
						# and extract the spam score
		#            if ($log_items[8] =~ "Yes, hits=(.*) required=([0-9\.]+)") 
						if ($log_items[8] =~ "Yes, score=(.*) required=([0-9\.]+)") 
							{$rejectspamavg += $1}
						mark_domain_rejected($proc);
		}

		elsif (($log_items[5] eq 'virus::clamav') or ($log_items[5] eq 'virus::clamdscan')) { $infectedcount++;$counts{$abshour}{$CATVIRUS}++;
						#extract the virus name
						if ($log_items[7] =~ "Virus found: (.*)" ) {$found_viruses{$1}++;}
						else {$found_viruses{$log_items[7]}++} #Some other message!!
						mark_domain_rejected($proc);
		}

		elsif ($log_items[5] eq 'queued') { $Accepttotal++;
						#extract the spam score
						# Remove count for rejectred as it looks as if it might get through!!
						$result= "queued";
						if ($log_items[8] =~ ".*score=([+-]?\\d+\.?\\d*).* required=([0-9\.]+)") {
							$score = trim($1);
							if ($score =~ /^[+-]?\d+\.?\d*$/ ) #check its numeric 
							{
								if ($score < $SATagLevel) { $hamcount++;$counts{$abshour}{$CATHAM}++;$hamavg += $score;}
								else {$spamcount++;$counts{$abshour}{$CATSPAM}++;$spamavg += $score;$result= "spam";}
							} else {
								print "Unexpected non numeric found in $proc:".$log_items[8]."($score)\n";
							}
						} else {
							# no SA score - treat it as ham
							$hamcount++;$counts{$abshour}{$CATHAM}++;
						}
						if ( ( $currentrcptdomain{ $proc } || '' ) ne '' ) {
										$byrcptdomain{ $currentrcptdomain{ $proc } }{ 'accept' }++ ;
										$currentrcptdomain{ $proc } = '' ;
						}
		}


		elsif ($log_items[5] eq 'tls') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'auth::auth_cvm_unix_local') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'earlytalker') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'uribl') {$RBLcount++;$counts{$abshour}{$CATRBLDNS}++;mark_domain_rejected($proc);$blacklistURL{get_domain($log_items[7])}++}

		elsif ($log_items[5] eq 'naughty') {
		 #Naughty plugin seems to span a number of rejection reasons - so we have to use the next but one log_item[7] to identify
		 if ($log_items[7] =~ m/(karma)/) {
			 $MiscDenyCount++;$counts{$abshour}{$CATKARMA}++;mark_domain_rejected($proc)}
		 elsif ($log_items[7] =~ m/(dnsbl)/){
			 $RBLcount++;$counts{$abshour}{$CATRBLDNS}++;mark_domain_rejected($proc);$blacklistURL{get_domain($log_items[7])}++}
		 elsif ($log_items[7] =~ m/(helo)/){
				$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}
		 else {
			 #Unidentified Naughty rejection
			 $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc);$unrecog_plugin{$log_items[5]."-".$log_items[7]}++}
		}
		elsif ($log_items[5] eq 'resolvable_fromhost') {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'loadcheck') {$MiscDenyCount++;$counts{$abshour}{$CATLOAD}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'karma') {$MiscDenyCount++;$counts{$abshour}{$CATKARMA}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'dmarc') {$MiscDenyCount++;$counts{$abshour}{$CATDMARC}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'relay') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'headers') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'mailfrom') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'badrcptto') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'helo') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'check_smtp_forward') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

		elsif ($log_items[5] eq 'sender_permitted_from') { $MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc)}

	 #Treat it as Unconf if not recognised
	 else {$MiscDenyCount++;$counts{$abshour}{$CATNONCONF}++;mark_domain_rejected($proc);$unrecog_plugin{$log_items[5]}++}
 } #Log[5] exists

		#Entry if not local send
		if ($localflag == 0) {
			if (length($log_items[4]) > 0){
				# Need to check here for multiple email addresses
				my @emails = split(",",lc($log_items[4]));
				if (scalar(@emails) > 1) {
					#Just pick the first local address to hang it on.
					# TEMP - just go for the first address until I can work out how to spot the 1st "local" one
					$usercounts{$emails[0]}{$result}++;
					$usercounts{$emails[0]}{"proc"} = $proc;
					#Compare with @domains array until we get a local one
					my $gotone = $false;
					foreach my $email (@emails){
						#Extract the domain from the email address
						my $fullemail = $email;
						$email = s/.*\@(.*)$/$1/;
						#and see if it is local
						if ($email =~ m/$alldomains/){
							$usercounts{lc($fullemail)}{$result}++;
							$usercounts{lc($fullemail)}{"proc"} = $proc;
							$gotone = $true;
							last;
						}
					}
					if (!$gotone) {
							$usercounts{'No internal email $proc'}{$result}++;
							$usercounts{'No internal email $proc'}{"proc"} = $proc;
					}
						
				} else {
					$usercounts{lc($log_items[4])}{$result}++;
					$usercounts{lc($log_items[4])}{"proc"} = $proc;
				}
			}
		}
   #exit if $emailnum == 15858;
   
}  #END OF MAIN LOOP

#total up grand total Columns
$nhour = floor( $start / 3600 );
while ( $nhour < $end / 3600 ) {
    $ncateg = 0; #past the where it came from columns
    while ( $ncateg < @categs) {
      #total columns
           $counts{$GRANDTOTAL}{$categs[$ncateg]} += $counts{$nhour}{$categs[$ncateg]};

      # and total rows
      if ( $ncateg < $categlen and $ncateg>=$countfromhere) {#skip initial columns of non final reasons
        $counts{$nhour}{$categs[@categs-2]} += $counts{$nhour}{$categs[$ncateg]};
      }
      $ncateg++
    }

    $nhour++;
}



#Compute row totals and row percentages
$nhour = floor( $start / 3600 );
while ( $nhour < $end / 3600 ) {
  $counts{$nhour}{$categs[@categs-1]} =  $counts{$nhour}{$categs[@categs-2]}*100/$totalexamined if $totalexamined;
  $nhour++;

}

#compute column percentages
    $ncateg = 0;
    while ( $ncateg < @categs) {
     if ($ncateg == @categs-1) {
           $counts{$PERCENT}{$categs[$ncateg]} = $counts{$GRANDTOTAL}{$categs[$ncateg-1]}*100/$totalexamined if $totalexamined;
     } else {
           $counts{$PERCENT}{$categs[$ncateg]} = $counts{$GRANDTOTAL}{$categs[$ncateg]}*100/$totalexamined if $totalexamined;
     }
      $ncateg++
    }

#compute sum of row percentages
$nhour = floor( $start / 3600 );
while ( $nhour < $end / 3600 ) {
  $counts{$GRANDTOTAL}{$categs[@categs-1]} += $counts{$nhour}{$categs[@categs-1]};
  $nhour++;

}

my $QueryNoLogTerse = ($totalexamined==0); #might indicate logterse not installed in qpsmtpd plugins

#Calculate some numbers

$spamavg       = $spamavg / $spamcount if $spamcount;
$rejectspamavg = $rejectspamavg / $above15 if $above15;
$hamavg = $hamavg / $hamcount if $hamcount;

#  RBL etc percent of total SMTP sessions

my $rblpercent           = ( ( $RBLcount / $totalexamined ) * 100 )           if $totalexamined;
my $PatternFilterpercent = ( ( $PatternFilterCount / $totalexamined ) * 100 ) if $totalexamined;
my $Miscpercent          = ( ( $MiscDenyCount / $totalexamined ) * 100 )      if $totalexamined;

#Spam and virus percent of total email downloaded
#Expressed as a % of total examined
my $spampercent          = ( ( $spamcount / $totalexamined ) * 100 )          if $totalexamined;
my $hampercent           = ( ( $hamcount / $totalexamined ) * 100 )           if $totalexamined;
my $hrsinperiod          = ( ( $end - $start ) / 3600 );
my $emailperhour = ( $totalexamined / $hrsinperiod ) if $totalexamined;
my $above15percent =  ( $above15 / $totalexamined * 100 ) if $totalexamined;
my $infectedpercent = ( ( $infectedcount / ($totalexamined) ) * 100 ) if $totalexamined;
my $AcceptPercent = ( ( $Accepttotal / ($totalexamined) ) * 100 ) if $totalexamined;

my $oldfh;

#Open Sendmail if we are mailing it
if ( $opt{'mail'} and !$disabled ) {
    open( SENDMAIL, "|$opt{'sendmail'} -oi -t -odq" )
      or die "Can't open sendmail: $!\n";
    print SENDMAIL "From: $opt{'from'}\n";
    print SENDMAIL "To: $opt{'mail'}\n";
    print SENDMAIL "Subject: Spam Filter Statistics from $hostname - ",
      strftime( "%F", localtime($start) ), "\n\n";
    $oldfh = select SENDMAIL;
}

my $telapsed = time - $tstart;

if ( !$disabled ) {

    #Output results

    # NEW - save the print to a variable so that it can be processed into html.
    #
    #Save current output selection and divert into variable
    #
		my $output;
		my $tablestr="";
		open(my $outputFH, '>', \$tablestr) or die; # This shouldn't fail
		my $oldFH = select $outputFH;


    print "SMEServer daily Anti-Virus and Spamfilter statistics from $hostname - ".strftime( "%F", localtime($start))."\n";
    print "----------------------------------------------------------------------------------", "\n\n";
    print "$0 Version : $opt{'version'}", "\n";
    print "Period Beginning : ", strftime( "%c", localtime($start) ), "\n";
    print "Period Ending    : ", strftime( "%c", localtime($end) ),   "\n";
    print "Clam Version/DB Count/Last DB update: ",`freshclam -V`;
    print "SpamAssassin Version : ",`spamassassin -V`;
    printf "Tag level: %3d; Reject level: %-3d $warnnoreject\n", $SATagLevel,$SARejectLevel;
    if ($HighLogLevel) {
      printf "*Loglevel is set to: ".$LogLevel. " - you only need it set to 6\n";
      printf "\tYou can set it this way:\n";
      printf "\tconfig setprop qpsmtpd LogLevel 6\n";
      printf "\tsignal-event email-update\n";
      printf "\tsv t /var/service/qpsmtpd\n";
    }
    printf "Reporting Period : %-.2f hrs\n", $hrsinperiod;
    printf "All SMTP connections accepted:%-8d          \n", $totalexamined;
    printf "Emails per hour              : %-8.1f/hr\n", $emailperhour || 0;
    printf "Average spam score (accepted): %-11.2f\n", $spamavg       || 0;
    printf "Average spam score (rejected): %-11.2f\n", $rejectspamavg || 0;
    printf "Average ham score            : %-11.2f\n", $hamavg        || 0;
    printf "Number of DMARC reporting emails sent:\t%-11d (not shown on table)\n", $DMARCSendCount      || 0;
    if ($hamcount != 0){ printf "Number of emails approved through DMARC:\t%-11d (%-3d%% of Ham count)\n", $DMARCOkCount|| 0,$DMARCOkCount*100/$hamcount || 0;}
    
    my $smeoptimizerprog = "/usr/local/smeoptimizer/SMEOptimizer.pl";
    if (-e $smeoptimizerprog) { 
			#smeoptimizer installed - get result of status
			my @smeoptimizerlines = split(/\n/,`/usr/local/smeoptimizer/SMEOptimizer.pl -status`);
			print("SMEOptimizer status:\n");
			print("\t".$smeoptimizerlines[6]."\n");
			print("\t".$smeoptimizerlines[7]."\n");
			print("\t".$smeoptimizerlines[8]."\n");
			print("\t".$smeoptimizerlines[9]."\n");
			print("\t".$smeoptimizerlines[10]."\n");
		}
			
        
    print "\nStatistics by Hour:\n";
    #
    # start by working out which colunns to show - tag the display array
    #
    $ncateg = 1;  ##skip the first column
    $finaldisplay[0] = $true;
    while ( $ncateg < $categlen) {
      if ($display[$ncateg] eq 'yes') { $finaldisplay[$ncateg] = $true }
      elsif ($display[$ncateg] eq 'no') { $finaldisplay[$ncateg] = $false }
      else {
        $finaldisplay[$ncateg] = ($counts{$GRANDTOTAL}{$categs[$ncateg]} != 0);
        if ($finaldisplay[$ncateg]) {
           #if it has been non zero and auto, then make it yes for the future.
           esmith::ConfigDB->open->get('mailstats')->set_prop($categs[$ncateg],'yes')
        }

      }
      $ncateg++
    }
    #make sure total and percentages are shown
    $finaldisplay[@categs-2] = $true;
    $finaldisplay[@categs-1] = $true;


    # and put together the print lines
        
    my $Line1;             #Full Line across the page
    my $Line2;             #Broken Line across the page
    my $Titles;            #Column headers
    my $Values;            #Values
    my $Totals;            #Corresponding totals
    my $Percent;           # and column percentages

    my $hour = floor( $start / 3600 );
    $Line1 = '';
    $Line2 = '';
    $Titles = '';
    $Values = '';
    $Totals = '';
    $Percent = '';
    while ( $hour < $end / 3600 ) {
         if ($hour == floor( $start / 3600 )){
            #Do all the once only things
             $ncateg = 0;
            while ( $ncateg < @categs) {
              if ($finaldisplay[$ncateg]){
                  $Line1 .= substr('---------------------',0,$colwidth[$ncateg]);
                  $Line2 .= substr('---------------------',0,$colwidth[$ncateg]-1);
                  $Line2 .= " ";
                  $Titles .= sprintf('%'.($colwidth[$ncateg]-1).'s',$categs[$ncateg])."|";
                  if ($ncateg == 0) {
                    $Totals .= substr('TOTALS                                   ',0,$colwidth[$ncateg]-2);
                    $Percent .= substr('PERCENTAGES                              ',0,$colwidth[$ncateg]-1);
                  } else {
                    # identify bottom right group and supress unless db->ShowGranPerc set
                    if ($ncateg==@categs-1){
                      $Totals .= sprintf('%'.$colwidth[$ncateg].'.1f',$counts{$GRANDTOTAL}{$categs[$ncateg]}).'%';
                    } else {
                      $Totals .= sprintf('%'.$colwidth[$ncateg].'d',$counts{$GRANDTOTAL}{$categs[$ncateg]});
                    }
                  $Percent .= sprintf('%'.($colwidth[$ncateg]-1).'.1f',$counts{$PERCENT}{$categs[$ncateg]}).'%';
                  }
              }
              $ncateg++
            }
        }

        $ncateg = 0;
        while ( $ncateg < @categs) {
          if ($finaldisplay[$ncateg]){
              if ($ncateg == 0) {
                $Values .= strftime( "%F, %H", localtime( $hour * 3600 ) )." "
              } elsif ($ncateg == @categs-1) {
                #percentages in last column
                $Values .= sprintf('%'.($colwidth[$ncateg]-2).'.1f',$counts{$hour}{$categs[$ncateg]})."%";
              } else {
                #body numbers
                   $Values .= sprintf('%'.($colwidth[$ncateg]-1).'d',$counts{$hour}{$categs[$ncateg]})." ";
               }
               if (($ncateg == @categs-1)){$Values=$Values."\n"} #&& ($hour == floor($end / 3600)-1)
          }
          $ncateg++
        }

        $hour++;
    }

    #
    # print it.
    #

		print $Line1."\n";
		#if ($makeHTMLemail eq "no" && $makeHTMLpage eq "no"){print $Line1."\n";}   #These lines mess up the HTML conversion ....
		print $Titles."\n";
		#if ($makeHTMLemail eq "no" && $makeHTMLpage eq "no"){print $Line2."\n";}   #ditto
		print $Line2."\n";
    print $Values;
    print $Line2."\n";
    print $Totals."\n";
    print $Percent."\n";
    print $Line1."\n";

    if ($localAccepttotal>0) {
      print "*Fetchml* means connections from Fetchmail delivering email\n";
    }
    print "*Local* means connections from workstations on local LAN.\n\n";
    print "*Non\.Conf\.* means sending mailserver did not conform to correct protocol";
    print "  or email was to non existant address.\n\n";

   if ($finaldisplay[$KarmaCateg]){
			print "*Karma* means email was rejected based on the mailserver's previous activities.\n\n";
   }


   if ($finaldisplay[$BadCountryCateg]){
        $BadCountries  = $cdb->get('qpsmtpd')->prop('BadCountries') || "*none*";
				print "*Geoip\.*:Bad Countries mask is:".$BadCountries."\n\n";
   }
   
   
   
   if (scalar keys %unrecog_plugin > 0){
		 #Show unrecog plugins found
		 print "*Unrecognised plugins found - categorised as Non-Conf\n";
		 foreach my $unrec (keys %unrecog_plugin){
			 print "\t$unrec\t($unrecog_plugin{$unrec})\n";
			}
			print "\n";
		}

    if ($QueryNoLogTerse) {
      print "* - as no records where found, it looks as though you may not have the *logterse* \nplugin running as part of qpsmtpd \n\n";
#      print " to enable it follow the instructions at .............................\n";
    }


    if ( !$RHSenabled or !$DNSenabled ) {

        # comment about RBL not set
        print
"* - This means that one or more of the possible spam black listing services\n    that are available have not been enabled.\n";
        print " You have not enabled:\n";

        if ( !$RHSenabled ) {
            print "    RHSBL\n";
        }

        if ( !$DNSenabled ) {
            print "    DNSBL\n";
        }


        print " To enable these you can use the following commands:\n";
        if ( !$RHSenabled ) {
            print " config setprop qpsmtpd RHSBL enabled\n";
        }

        if ( !$DNSenabled ) {
            print " config setprop qpsmtpd DNSBL enabled\n";
        }

        # there so much templates to expand... (PS)
        print " Followed by:\n signal-event email-update and\n sv t /var/service/qpsmtpd\n\n";
    }

#    if ($Webmailsendtotal > 0) {print "If you have the mailman contrib installed, then the webmail totals might include some mailman emails\n"}

    # time to do a 'by recipient domain' report
    print "Incoming mails by recipient domains usage\n";
    print "-----------------------------------------\n";
    print
        "Domains                      Type       Total  Denied XferErr Accept \%accept\n";
    print
        "---------------------------- ---------- ------ ------ ------- ------ -------\n";
    my %total = (
        total  => 0,
        deny   => 0,
        xfer   => 0,
        accept => 0,
    );
    foreach my $domain (
        sort {
            join( "\.",     reverse( split /\./, $a ) ) cmp
                join( "\.", reverse( split /\./, $b ) )
        } keys %byrcptdomain
        )
    {
        next if ( ( $byrcptdomain{$domain}{'total'} || 0 ) == 0 );
        my $tp = $byrcptdomain{$domain}{'type'}   || 'other';
        my $to = $byrcptdomain{$domain}{'total'}  || 0;
        my $de = $byrcptdomain{$domain}{'deny'}   || 0;
        my $xr = $byrcptdomain{$domain}{'xfer'}   || 0;
        my $ac = $byrcptdomain{$domain}{'accept'} || 0;
        printf "%-28s %-10s %6d %6d %7d %6d %6.2f%%\n", $domain, $tp, $to,
            $de, $xr, $ac, $ac * 100 / $to;
        $total{'total'}  += $to;
        $total{'deny'}   += $de;
        $total{'xfer'}   += $xr;
        $total{'accept'} += $ac;
    }
    print
        "---------------------------- ---------- ------ ------- ------ ------ -------\n";

    # $total{ 'total' } can be equal to 0, bad for divisions...
    my $perc1 = 0;
    my $perc2 = 0;


    if ( $total{'total'} != 0 ) {
        $perc1 = $total{'accept'} * 100 / $total{'total'};
        $perc2 = ( ( $total{'total'} + $morethanonercpt ) / $total{'total'} );
    }
    printf
        "Total                                   %6d %6d %7d %6d %6.2f%%\n\n",
        $total{'total'}, $total{'deny'}, $total{'xfer'}, $total{'accept'},
        $perc1;
    printf
        "%d mails were processed for %d Recipients\nThe average recipients by mail is %4.2f\n\n",
        $total{'total'}, ( $total{'total'} + $morethanonercpt ), $perc2;

    if ( $infectedcount > 0 ) {
        show_virus_variants();
    }


    if ($enableqpsmtpdcodes) {show_qpsmtpd_codes();}

    if ($enableSARules) {show_SARules_codes();}

    if ($enableGeoiptable and (($total_countries > 0) or $finaldisplay[$BadCountryCateg])){show_Geoip_results();}

    if ($enablejunkMailList) {List_Junkmail();}
    
    if ($enableblacklist) {show_blacklist_counts();}
    
    show_user_stats();

    print "\nReport generated in $telapsed sec.\n";

    if ($savedata) { save_data(); }
    else
      { print "No data saved -  if you want to save data to a MySQL database, then please use:\n".
	"config setprop mailstats SaveDataToMySQL yes\n";
      }

		select $oldFH;
		close $outputFH;
		if ($makeHTMLemail eq "no" or $makeHTMLemail eq "both") {print $tablestr}
		if ($makeHTMLemail eq "yes" or $makeHTMLemail eq "both" or $makeHTMLpage eq "yes"){
			#Convert text to html and send it
			require CGI;
			require TextToHTML;
			my $cgi = new CGI;
			my $text = $tablestr;
			my %paramhash = (default_link_dict=>'',make_tables=>1,preformat_trigger_lines=>10,tab_width=>20);
			my $conv = new HTML::TextToHTML();
			$conv->args(default_link_dict=>'',make_tables=>1,preformat_trigger_lines=>2,preformat_whitespace_min=>2,
										underline_length_tolerance=>1);

			my $html = $cgi->header();
			$html .="<!DOCTYPE html> <html>\n";
			$html .=  "<head><title>Mailstats -".strftime( "%F", localtime($start) )."</title>";
			$html .=  "<link rel='stylesheet' type='text/css' href='mailstats.css' /></head>\n";
			$html .= "<body>\n";
			$html .= $conv->process_chunk($text);
			$html .= "</body></html>\n";
			if ($makeHTMLemail eq "yes" or $makeHTMLemail eq "both" ) {print $html}
			#And drop it into a file
			if ($makeHTMLpage eq "yes") {
				my $filename = "mailstats.html";
				open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";
				print $fh $html;
				close $fh;
			}
			
		}


    #Close Sendmail if it was opened
    if ( $opt{'mail'} ) {
        select $oldfh;
        close(SENDMAIL);
    }

}  ##report disabled

#All done
exit 0;

#############################################################################
# Subroutines ###############################################################
#############################################################################


################################################
# Determine analysis period (start and end time)
################################################
sub analysis_period {
    my $startdate = shift;
    my $enddate   = shift;

    my $secsininterval = 86400;  #daily default
    my $time;

    if ($cdb->get('mailstats'))
    {
      my $interval = $cdb->get('mailstats')->prop('Interval') || 'daily'; #"fortnightly"; #"daily";# #; TEMP!!
      if ($interval eq "weekly") {
        $secsininterval = 86400*7;
      } elsif ($interval eq "fortnightly") {
        $secsininterval = 86400*14;
      } elsif ($interval eq "monthly") {
        $secsininterval = 86400*30;
      } elsif ($interval =~m/\d+/) {
        $secsininterval = $interval*3600;
      };
      my $base = $cdb->get('mailstats')->prop('Base') || 'Midnight'; 
      my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
                                                localtime(time);
      if ($base eq "Midnight"){
      	$sec = 0;$min=0;$hour=0;
      } elsif ($base eq "Midday"){
      	$sec = 0;$min=0;$hour=12;
      } elsif ($base =~m/\d+/){
        $sec=0;$min=0;$hour=$base;
      };
      #$mday="05"; #$mday="03"; #$mday="16"; #Temp!!
      $time = timelocal($sec,$min,$hour,$mday,$mon,$year);
    }
    
    my $start = str2time( $startdate );
    my $end   = $enddate ? str2time( $enddate ) :
     	$startdate ? $start + $secsininterval : $time;
    $start = $startdate ? $start : $end - $secsininterval;
    return ( $start > $end ) ? ( $end, $start ) : ( $start, $end );
}

sub dbg {
    my $msg = shift;
    my $time = scalar localtime;
		$msg = $time.":".$msg."\n";
    if ( $opt{debug} ) {
        print STDERR $msg;
    }
}

sub List_Junkmail {

    #
    # Show how many junkmails in each user's junkmail folder.
    #
    use esmith::AccountsDB;
    my $adb = esmith::AccountsDB->open_ro;
    my $entry;
    foreach my $user ( $adb->users ) {
        my $found = 0;
        my $junkmail_dir =
          "/home/e-smith/files/users/" . $user->key . "/Maildir/.junkmail";
        foreach my $dir (qw(new cur)) {

            # Now get the content list for the directory.
            if ( opendir( QDIR, "$junkmail_dir/$dir" ) ) {
                while ( $entry = readdir(QDIR) ) {
                    next if $entry =~ /^\./;
                    $found++;
                }
                closedir(QDIR);
            }
        }
        if ( $found != 0 ) {
            $junkcount{ $user->key } = $found;
        }
    }
    my $i = keys %junkcount;
    if ( $i > 0 ) {
        print("\nJunk Mails left in folder:\n");
        print("---------------------------\n");
        print("Count\tUser\n");
        print("-------------------------\n");
        foreach my $thisuser (
            sort { $junkcount{$b} <=> $junkcount{$a} }
            keys %junkcount
          )
        {
            printf "%d", $junkcount{$thisuser};
            print "\t" . $thisuser . "\n";
        }
        print("-------------------------\n");
    }
    else {
        print "***No junkmail folders with emails***\n";
    }
}

sub show_virus_variants

#
# Show a league table of the different virus types found today
#

{
		my $line = "------------------------------------------------------------------------\n";
    print("\nVirus Statistics by name:\n");
    print($line);
    foreach my $virus (sort { $found_viruses{$b} <=> $found_viruses{$a} }
                keys %found_viruses)
    {
			if (index($virus,"Sanesecurity") !=-1 or index($virus,"UNOFFICIAL") !=-1){
			print "Rejected $found_viruses{$virus}\thttp://sane.mxuptime.com/s.aspx?id=$virus\n";
		} else {
			print "Rejected $found_viruses{$virus}\t$virus\n";
		}
			
    }
    print($line);
}

sub show_qpsmtpd_codes

#
# Show a league table of the qpsmtpd result codes found today
#

{
		my $line = "---------------------------------------------\n";
    print("\nQpsmtpd codes league table:\n");
    print($line);
    print("Count\tPercent\tReason\n");
    print($line);
    foreach my $qpcode (sort { $found_qpcodes{$b} <=> $found_qpcodes{$a} }
                keys %found_qpcodes)
    {
    print "$found_qpcodes{$qpcode}\t".sprintf('%4.1f',$found_qpcodes{$qpcode}*100/$totalexamined)."%\t\t$qpcode\n" if $totalexamined;
    }
    print($line);
}

sub  trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s };

sub get_domain 
{	my $url = shift;
	$url =~ s!^\(dnsbl\)\s!!;
	$url =~ s!^.*https?://(?:www\.)?!!i;
	$url =~ s!/.*!!;
	$url =~ s/[\?\#\:].*//;
	$url =~ s/^([\d]{1,3}.){4}//;
	my $domain = trim($url);
	return $domain;
}

sub show_blacklist_counts

#
# Show a sorted league table of the blacklist URL counts
#

{
		my $line = "------------------\n";
	  print("\nBlacklist details:\n");
    print($line);
    if ($cdb->get('qpsmtpd')->prop("RHSBL") eq "enabled") {print "RBLLIST:".$cdb->get('qpsmtpd')->prop("RBLList")."\n";}
    if ($cdb->get('qpsmtpd')->prop("URIBL") eq "enabled") {print "UBLLIST:".$cdb->get('qpsmtpd')->prop("UBLList")."\n";}
    if (!$cdb->get('qpsmtpd')->prop("SBLList") eq "") {print "SBLLIST:".$cdb->get('qpsmtpd')->prop("SBLList")."\n";}
    print($line);
    print("Count\tURL\n");
    print($line);
    foreach my $blcode (sort { $blacklistURL{$b} <=> $blacklistURL{$a} }
                keys %blacklistURL)
    {
			print sprintf('%3u',$blacklistURL{$blcode})."\t$blcode\n";
    }
    print($line);
}


sub show_user_stats

#
# Show a sorted league table of the user counts
#

{
		#Compute totals for each entry
		my $grandtotals=0;
		my $totalqueued=0;
		my $totalspam=0;
		my $totalrejected=0;
		foreach my $user (keys %usercounts){
			$usercounts{$user}{"queued"} = 0 if !(exists $usercounts{$user}{"queued"});
			$usercounts{$user}{"rejected"} = 0 if !(exists $usercounts{$user}{"rejected"});
			$usercounts{$user}{"spam"} = 0 if !(exists $usercounts{$user}{"spam"});
			$usercounts{$user}{"totals"} = $usercounts{$user}{"queued"}+$usercounts{$user}{"rejected"}+$usercounts{$user}{"spam"};
			$grandtotals += $usercounts{$user}{"totals"};
			$totalspam += $usercounts{$user}{"spam"};
			$totalqueued += $usercounts{$user}{"queued"};
			$totalrejected += $usercounts{$user}{"rejected"};
		}
		my $line = "--------------------------------------------------\n";
    print("\nStatistics by email address received:\n");
    print($line);
    print("Queued\tRejected\tSpam tagged\tEmail Address\n");
    print($line);
    foreach my $user (sort { $usercounts{$b}{"totals"} <=> $usercounts{$a}{"totals"} }
                keys %usercounts)
    {
			print sprintf('%3u',$usercounts{$user}{"queued"})."\t".sprintf('%3u',$usercounts{$user}{"rejected"})."\t\t".sprintf('%3u',$usercounts{$user}{"spam"})."\t\t$user\n";
    }  
    print($line);
		print sprintf('%3u',$totalqueued)."\t".sprintf('%3u',$totalrejected)."\t\t".sprintf('%3u',$totalspam)."\n";
    print($line);
		
    
}

sub show_Geoip_results
#
# Show league table of GEoip results
#
{

    my ($percentthreshold);
    my ($reject);
    my ($percent);
    my ($totalpercent)=0;
    if ($cdb->get('mailstats')){
        $percentthreshold = $cdb->get('mailstats')->prop("GeoipCutoffPercent") || 0.5;
    } else {
      $percentthreshold = 0.5;
    }
    if ($total_countries > 0) {
			my $line = "---------------------------------------------\n";
			print("\nGeoip results: (cutoff at $percentthreshold%) \n");
			print($line);
			print("Country\tPercent\tCount\tRejected?\n");
			print($line);
			foreach my $country (sort { $found_countries{$b} <=> $found_countries{$a} }
									keys %found_countries)
			{
				 $percent = $found_countries{$country} * 100 / $total_countries
						if $total_countries;
				 $totalpercent = $totalpercent + $percent;
				 if (index($BadCountries, $country) != -1) {$reject = "*";} else { $reject = " ";}
				 if ( $percent >= $percentthreshold ) {
						 print "$country\t\t"
							 . sprintf( '%4.1f', $percent )
							 . "%\t\t$found_countries{$country}","\t$reject\n"
							 if $total_countries;
				 }	
				 
			}
			print($line);
			my ($showtotals);
			if ($cdb->get('mailstats')){
					$showtotals = ((($cdb->get('mailstats')->prop("ShowLeagueTotals")|| 'yes')) eq "yes"); 
			} else {
				$showtotals = $true;
			}

			if ($showtotals){
				print "TOTALS\t\t".sprintf("%4.1f",$totalpercent)."%\t\t$total_countries\n";
				print($line);
			}
		}
}

sub show_SARules_codes

#
# Show a league table of the SARules result codes found today
# suppress any lower than DB mailstats/SARulePercentThreshold
#

{
    my ($percentthreshold);
    my ($defaultpercentthreshold);
    my ($totalpercent) = 0;
		
		if ($sum_SARules > 0){
			
			if ($totalexamined >0 and $sum_SARules*100/$totalexamined > $SARulethresholdPercent) {
				$defaultpercentthreshold = $maxcutoff
			} else {
				$defaultpercentthreshold = $mincutoff
			}
			if ($cdb->get('mailstats')){
					$percentthreshold = $cdb->get('mailstats')->prop("SARulePercentThreshold") || $defaultpercentthreshold;
				} else {
					$percentthreshold = $defaultpercentthreshold
				}
			my $line = "---------------------------------------------\n";
			print("\nSpamassassin Rules:(cutoff at ".sprintf('%4.1f',$percentthreshold)."%)\n");
			print($line);
			print("Count\tPercent\tScore\t\t\n");
			print($line);
			foreach my $SARule (sort { $found_SARules{$b}{'count'} <=> $found_SARules{$a}{'count'} }
									keys %found_SARules)
			{
				my $percent = $found_SARules{$SARule}{'count'} * 100 / $totalexamined if $totalexamined;
				my $avehits = $found_SARules{$SARule}{'totalhits'} /
				$found_SARules{$SARule}{'count'}
					if $found_SARules{$SARule}{'count'};
				if ( $percent >= $percentthreshold ) {
					print "$found_SARules{$SARule}{'count'}\t"
					. sprintf( '%4.1f', $percent ) . "%\t"
					. sprintf( '%4.1f', $avehits )
					. "\t$SARule\n"
						if $totalexamined;
	}
			}
			print($line);
			my ($showtotals);
			if ($cdb->get('mailstats')){
					$showtotals = ((($cdb->get('mailstats')->prop("ShowLeagueTotals")|| 'yes')) eq "yes"); 
			} else {
				$showtotals = $true;
			}

			if ($showtotals){
				print "$totalexamined\t(TOTALS)\n";
			print($line);
			}
			print "\n";
		}


}

sub mark_domain_rejected

#
# Tag domain as having a rejected email
#
{
my ($proc) = @_;
if ( ( $currentrcptdomain{ $proc } || '' ) ne '' ) {
            $byrcptdomain{ $currentrcptdomain{ $proc } }{ 'deny' }++ ;
            $currentrcptdomain{ $proc } = '' ;
        }
}

sub mark_domain_err

  #
  # Tag domain as having an error on email transfer
  #
{
    my ($proc) = @_;
    if ( ( $currentrcptdomain{$proc} || '' ) ne '' ) {
        $byrcptdomain{ $currentrcptdomain{$proc} }{'xfer'}++;
        $currentrcptdomain{$proc} = '';
    }
}

sub add_in_domain

  #
  # add recipient domain into hash
  #
{
    my ($proc) = @_;

    #split to just domain bit.
    $currentrcptdomain{$proc} =~ s/.*@//;
    $currentrcptdomain{$proc} =~ s/[^\w\-\.]//g;
    $currentrcptdomain{$proc} =~ s/>//g;
    my $NotableDomain = 0;
    if ( defined( $byrcptdomain{ $currentrcptdomain{$proc} }{'type'} ) ) {
        $NotableDomain = 1;
    }
    else {
        foreach (@extdomain) {
            if ( $currentrcptdomain{$proc} =~ m/$_$/ ) {
                $NotableDomain = 1;
                last;
            }
        }
    }
    if ( !$NotableDomain ) {

        # check for outgoing email
        if   ( $localflag == 1 ) { $currentrcptdomain{$proc} = 'Outgoing' }
        else                     { $currentrcptdomain{$proc} = 'Others' }
    }
    else {
        if ( $localflag == 1 ) { $currentrcptdomain{$proc} = 'Internal' }
    }
    $byrcptdomain{ $currentrcptdomain{$proc} }{'total'}++;
}

sub save_data

  #
  # Save the data to a MySQL database
  #
{
    use DBI;
    my $tstart = time;
    my $DBname = "mailstats";
    my $host = esmith::ConfigDB->open_ro->get('mailstats')->prop('DBHost') || "localhost";
    my $port = esmith::ConfigDB->open_ro->get('mailstats')->prop('DBPort') || "3306";
    print "Saving data..";
    my $dbh = DBI->connect( "DBI:mysql:database=$DBname;host=$host;port=$port",
        "mailstats", "mailstats" )
      or die "Cannot open mailstats db - has it beeen created?";

    my $hour = floor( $start / 3600 );
    my $reportdate = strftime( "%F", localtime( $hour * 3600 ) );
    my $dateid = get_dateid($dbh,$reportdate);
    my $reccount = 0;           #count number of records written
    my $servername = esmith::ConfigDB->open_ro->get('SystemName')->value . "."
      . esmith::ConfigDB->open_ro->get('DomainName')->value;
    # now fill in day related stats  - must always check for it already there
    # incase the module is run more than once in a day
    my $SAScoresid = check_date_rec($dbh,"SAscores",$dateid,$servername);
    $dbh->do( "UPDATE SAscores SET ".
          "acceptedcount=".$spamcount.
          ",rejectedcount=".$above15.
          ",hamcount=".$hamcount.
          ",acceptedscore=".$spamhits.
          ",rejectedscore=".$rejectspamhits.
          ",hamscore=".$hamhits.
          ",totalsmtp=".$totalexamined.
          ",totalrecip=".$recipcount.
          ",servername='".$servername.
      "' WHERE SAscoresid =".$SAScoresid);
    # Junkmail stats
    # delete if already there
    $dbh->do("DELETE from JunkMailStats WHERE dateid = ".$dateid." AND servername='".$servername."'");
    # and add records
    foreach my $thisuser (keys %junkcount){
    $dbh->do("INSERT INTO JunkMailStats (dateid,user,count,servername) VALUES ('".
      $dateid."','".$thisuser."','".$junkcount{$thisuser}."','".$servername."')");
      $reccount++;
    }
    #SA rules - delete any first
    $dbh->do("DELETE from SARules WHERE dateid = ".$dateid." AND servername='".$servername."'");
    # and add records
    foreach my $thisrule (keys %found_SARules){
    	$dbh->do("INSERT INTO SARules (dateid,rule,count,totalhits,servername) VALUES ('".
    		$dateid."','".$thisrule."','".$found_SARules{$thisrule}{'count'}."','".
    		$found_SARules{$thisrule}{'totalhits'}."','".$servername."')");
   		$reccount++;
    }
    #qpsmtpd result codes
    $dbh->do("DELETE from qpsmtpdcodes WHERE dateid = ".$dateid." AND servername='".$servername."'");
    # and add records
    foreach my $thiscode (keys %found_qpcodes){
	    $dbh->do("INSERT INTO qpsmtpdcodes (dateid,reason,count,servername) VALUES ('".
    	  $dateid."','".$thiscode."','".$found_qpcodes{$thiscode}."','".$servername."')");
      	$reccount++;
}
    # virus stats
    $dbh->do("DELETE from VirusStats WHERE dateid = ".$dateid." AND servername='".$servername."'");
    # and add records
    foreach my $thisvirus (keys %found_viruses){
	    $dbh->do("INSERT INTO VirusStats (dateid,descr,count,servername) VALUES ('".
    	  $dateid."','".$thisvirus."','".$found_viruses{$thisvirus}."','".$servername."')");
    	$reccount++;

    }
    # domain details
    $dbh->do("DELETE from domains WHERE dateid = ".$dateid." AND servername='".$servername."'");
    # and add records
    foreach my $domain (keys %byrcptdomain){
	    next if ( ( $byrcptdomain{$domain}{'total'} || 0 ) == 0 );
	    $dbh->do("INSERT INTO domains (dateid,domain,type,total,denied,xfererr,accept,servername) VALUES ('".
	      $dateid."','".$domain."','".($byrcptdomain{$domain}{'type'}||'other')."','"
	      .$byrcptdomain{$domain}{'total'}."','"
	      .($byrcptdomain{$domain}{'deny'}||0)."','"
	      .($byrcptdomain{$domain}{'xfer'}||0)."','"
	      .($byrcptdomain{$domain}{'accept'}||0)."','"
	      .$servername
	      ."')");
      $reccount++;

	}
    # finally  - the hourly breakdown
    # need to remember here that the date might change during the 24 hour span
    my $nhour = floor( $start / 3600 );
	my $ncateg;
	while ( $nhour < $end / 3600 ) {
        #see if the time record has been created
 #       print strftime("%H",localtime( $nhour * 3600 ) ).":00:00\n";
	    my $sth =
	      $dbh->prepare( "SELECT timeid FROM time WHERE time = '" . strftime("%H",localtime( $nhour * 3600 ) ).":00:00'");
	    $sth->execute();
	    if ( $sth->rows == 0 ) {
	      #create entry
	      $dbh->do( "INSERT INTO time (time) VALUES ('" .strftime("%H",localtime( $nhour * 3600 ) ).":00:00')" );
	      # and pick up timeid
	      $sth = $dbh->prepare("SELECT last_insert_id() AS timeid FROM time");
	      $sth->execute();
	      $reccount++;
	    }
	    my $timerec = $sth->fetchrow_hashref();
	    my $timeid  = $timerec->{"timeid"};
	    $ncateg = 0;
	    # and extract date from first column of $count array
	    my $currentdate = strftime( "%F", localtime( $hour * 3600 ) );
  #	    print "$currentdate.\n";
	    if ($currentdate ne $reportdate) {
	      #same as before?
	      $dateid = get_dateid($dbh,$currentdate);
	      $reportdate = $currentdate;
	    }
        # delete for this date and time
        $dbh->do("DELETE from ColumnStats WHERE dateid = ".$dateid." AND timeid = ".$timeid." AND servername='".$servername."'");
	    while ( $ncateg < @categs-1 ) {
            # then add in each entry
            if (($counts{$nhour}{$categs[$ncateg]} || 0) != 0) {
	            $dbh->do("INSERT INTO ColumnStats (dateid,timeid,descr,count,servername) VALUES ("
	            .$dateid.",".$timeid.",'".$categs[$ncateg]."',"
	            .$counts{$nhour}{$categs[$ncateg]}.",'".$servername."')");
	        $reccount++;
        }

# print("INSERT INTO ColumnStats (dateid,timeid,descr,count) VALUES ("
#            .$dateid.",".$timeid.",'".$categs[$ncateg]."',"
#            .$counts{$nhour}{$categs[$ncateg]}.")\n");

	        $ncateg++;
	    }
    	$nhour++;
	}
	# and write out the log lines saved - only if html wanted
	if ($makeHTMLemail eq 'yes' or $makeHTMLemail eq 'both' or $makeHTMLpage eq 'yes'){
		foreach my $logid (keys %LogLines){
			$reccount++; 
			#Extract from keys
			my $extract = $logid;
			$extract =~/^(.*)-(.*):(.*)$/;
			my $Log64n = $1;
			my $LogMailId = $2;
			my $LogSeq = $3;
			my $LogLine = $dbh->quote($LogLines{$logid});
			my $sql = "INSERT INTO LogData (Log64n,MailID,Sequence,LogStr) VALUES ('";
			$sql .= $Log64n."','".$LogMailId."','".$LogSeq."',".$LogLine.")";
			$dbh->do($sql) or die($sql);
		}
		$dbh->disconnect();
		$telapsed = time - $tstart;
		print "Saved $reccount records in $telapsed sec.";
	}
}

sub check_date_rec

  #
  # check that a specific dated rec is there, create if not
  #
{
    my ( $dbh, $table, $dateid ) = @_;
    my $sth =
      $dbh->prepare(
        "SELECT " . $table . "id FROM ".$table." WHERE dateid = '$dateid'" );
    $sth->execute();
    if ( $sth->rows == 0 ) {
        #create entry
        $dbh->do( "INSERT INTO ".$table." (dateid) VALUES ('" . $dateid . "')" );
        # and pick up recordid
        $sth = $dbh->prepare("SELECT last_insert_id() AS ".$table."id FROM ".$table);
        $sth->execute();
    }
    my $rec = $sth->fetchrow_hashref();
    $rec->{$table."id"};   #return the id of the reocrd (new or not)
 }

 sub check_time_rec

  #
  # check that a specific dated amd timed rec is there, create if not
  #
{
    my ( $dbh, $table, $dateid, $timeid ) = @_;
    my $sth =
      $dbh->prepare(
        "SELECT " . $table . "id FROM ".$table." WHERE dateid = '$dateid' AND timeid = ".$timeid );
    $sth->execute();
    if ( $sth->rows == 0 ) {
        #create entry
        $dbh->do( "INSERT INTO ".$table." (dateid,timeid) VALUES ('" . $dateid . "', '".$timeid."')" );
        # and pick up recordid
        $sth = $dbh->prepare("SELECT last_insert_id() AS ".$table."id FROM ".$table);
        $sth->execute();
    }
    my $rec = $sth->fetchrow_hashref();
    $rec->{$table."id"};   #return the id of the record (new or not)
 }

sub get_dateid

#
# Check that date is in db, and return corresponding id
#
{
	my ($dbh,$reportdate) = @_;
    my $sth =
      $dbh->prepare( "SELECT dateid FROM date WHERE date = '" . $reportdate."'" );
    $sth->execute();
    if ( $sth->rows == 0 ) {
        #create entry
        $dbh->do( "INSERT INTO date (date) VALUES ('" . $reportdate . "')" );
        # and pick up dateid
        $sth = $dbh->prepare("SELECT last_insert_id() AS dateid FROM date");
        $sth->execute();
    }
    my $daterec = $sth->fetchrow_hashref();
    $daterec->{"dateid"};
 }
 
 sub dump_entries
 {
	my $msg = shift;
	#if ($opt{debug} == 1){exit;}
}

#sub test_for_private_ip {
	#use NetAddr::IP;
	#my $ip = shift;
	#$ip =~ s/^\D*(([0-9]{1,3}\.){3}[0-9]{1,3}).*/$1/e;
	#print "\nIP:$ip";
	#my $nip = NetAddr::IP->new($ip);
	#if ($nip){
		#if ( $nip->is_rfc1918() ){
				#return 1;
		#} else { return 0} 
	#} else { return 0}
#}


sub test_for_private_ip {
     use NetAddr::IP;
     $_ = shift;
     return unless /(\d+\.\d+\.\d+\.\d+)/;
     my $ip = NetAddr::IP->new($1);
     return unless $ip;
     return $ip->is_rfc1918();
}


