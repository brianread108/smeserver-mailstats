#!/usr/bin/perl -w
#############################################################################
#
# This script provides daily mailserver mail rejection and acceptance statistics.
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
# bjr - 18Oct16 - More progress towards html output
# bjr - 16Dec16 - Fix dnsbl code to deal with psbl.surriel.com  - Bug 9717
# bjr - 16Dec16 - Change geopip table code to show even if no exclusions found (assuming geoip data found) - Bug 9888
# bjr - 21Dec16 - Further geoip fixes as suggested by Jean-Philippe Pialasse  - See Bug 9888
# bjr - 07Aug17 - Fix up log items tags so that only relevant items shown on detail web page
# bjr - 12Dec17 - Add in deleting old data in tables. - added servername to data table.
# bjr - 16Dec17 - Add in date to html file name so that can keep previous versions - add in next and prev on web page
# bjr - 23Dec17 - Lots of changes to html to make conformant and internally consistent
#
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
#			 / HTMLEmail - "yes", "no", "both" - default is "No" - Send email in HTML
#			 / HTMLPage - "yes"  / "no"  - default is "yes" if HTMLEmail is "yes" or "both" otherwise "no"
#			 / daysKeepLogData - default is 30 -(days) Delete earlier data
#############################################################################
#
#
#  TODO
#
# 1. Delete loglines records from any previous run of same table - Done?
# 2. Check for duplicate logid when "Accepted connection" occurs and make it unique - Not needed?
# 2.1 - Upload sources etc to gihub - DONE - 14thDec17 - see https://github.com/brianread108/smeserver-mailstats/
# 3. Delete earlier logData and LogDataCounts records - up to parameter daysKeepLogData - Done
# 4. Generate unique html page - keep up to daysKeepHTMLPage - add in next and prev to web page.
# 5. Tag totals columns and rows seperatatly
# 6. Check truncation of emails when no <> in email hit list table
# 7. Colour code each set of logs for a connection - Done
# 8. Build RPM (inc config webpage in /opt/mailstats (or somesuch place)
# 9. Check formatting of text version
# 10. Add in the links for all the other tables
# 11. Add in links to wiki and also github
#
#
# internal modules (part of core perl distribution)
# Needs (if HTML set)
# yum install perl-HTML-Template --enablerepo=epel
# and need mailstats.tmpl in the same directory as the mailstats.pl
#
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

my $hostname = hostname();
my $cdb = esmith::ConfigDB->open_ro or die "Couldn't open ConfigDB : $!\n";

my $htmlpagepath = "/home/e-smith/files/ibays/mesdb/html/mailstats/";

my $true  = 1;
my $false = 0;

#and see if mailstats are disabled
my $disabled;
if ( $cdb->get('mailstats') ) {
    $disabled =
      !( ( $cdb->get('mailstats')->prop('Status') || 'enabled' ) eq 'enabled' );
}
else {
    my $db = esmith::ConfigDB->open;
    my $record =
      $db->new_record( 'mailstats',
        { type => 'report', Status => 'enabled', Email => 'admin' } );
    $cdb = esmith::ConfigDB->open_ro
      or die
      "Couldn't open ConfigDB : $!\n";    #Open up again to pick up new record
    $disabled = $false;
}

#Configuration section
my %opt = (
    version  => '0.8.0',                  # please update at each change.
    debug    => 0,                        # guess what ?
    sendmail => '/usr/sbin/sendmail',     # Path to sendmail stub
    from     => 'spamfilter-stats',       # Who is the mail from
    mail => $cdb->get('mailstats')->prop('Email')
      || 'admin',                         # mailstats email recipient
    timezone => `date +%z`,
    params => @ARGV
);

my $FetchmailIP = '127.0.0.200';    #Apparent Ip address of fetchmail deliveries
my $WebmailIP   = '127.0.0.1';      #Apparent Ip of Webmail sender
my $localhost   = 'localhost';      #Apparent sender for webmail
my $FETCHMAIL   = 'FETCHMAIL'
  ; #Sender from fetchmail when Ip address not 127.0.0.200 - when qpsmtpd denies the email
my $MAILMAN     = "bounces"; #sender when mailman sending when orig is localhost
my $DMARCDomain = "dmarc"
  ; #Pattern to recognised DMARC sent emails (this not very reliable, as the email address could be anything)
my $DMARCOkPattern = "dmarc: pass";    #Pattern to use to detect DMARC approval
my $localIPregexp =
".*((127\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.)).*";
my $MinCol       = 6;                  #Minimum column width
my $HourColWidth = 16;                 #Date and time column width

my $SARulethresholdPercent =   10;    #If Sa rules less than this of total emails, then cutoff reduced
my $maxcutoff = 1;      #max percent cutoff applied
my $mincutoff = 0.2;    #min percent cutoff applied

my $tstart = time;

#Local variables
my $YEAR = ( localtime(time) )[5];    # this is years since 1900

my $total          = 0;
my $spamcount      = 0;
my $spamavg        = 0;
my $spamhits       = 0;
my $hamcount       = 0;
my $hamavg         = 0;
my $hamhits        = 0;
my $rejectspamavg  = 0;
my $rejectspamhits = 0;

my $Accepttotal      = 0;
my $localAccepttotal = 0;    #Fetchmail connections
my $localsendtotal   = 0;    #Connections from local PCs
my $totalexamined    = 0;    #total download + RBL etc
my $WebMailsendtotal = 0;    #total from Webmail
my $mailmansendcount = 0;    #total from mailman
my $DMARCSendCount   = 0;    #total DMARC reporting emails sent (approx)
my $DMARCOkCount     = 0;    #Total emails approved through DMARC

my %found_viruses  = ();
my %found_qpcodes  = ();
my %found_SARules  = ();
my %junkcount      = ();
my %unrecog_plugin = ();
my %blacklistURL   = ();     #Count of use of each blacklist rhsbl/dnsbl/uribl
my %usercounts     = ()
  ; #Count per received email of sucessful delivery, queued spam and deleted Spam, and rejected

# replaced by...
my %counts   = ();    #Hold all counts in 2-D matrix
my %count_id = ();    #Ids for index into list of mailids for each count
my @display =
  ();    #used to switch on and off columns  - yes, no or auto for each category
my @colwidth = ();    #width of each column
     #(auto means only if non zero) - populated from possible db entries
my @finaldisplay = ();    #final decision on display or not  - true or false

# Array used to hold the link betwen the count_id and the Mailid (i.e note which email is in each count)
# emptied into the MySQL DB in the save routine.
my @emails_per_count_id;

#count column names, used for headings  - also used for DB mailstats property names
my $CATHOUR      = 'Hour';
my $CATFETCHMAIL = 'Fetchmail';
my $CATWEBMAIL   = 'WebMail';
my $CATMAILMAN   = 'Mailman';
my $CATLOCAL     = 'Local';
my $CATRELAY     = "Relay";

# border between where it came from and where it ended..
my $countfromhere = 6;    #Temp - Check this not moved!!

my $CATVIRUS        = 'Virus';
my $CATRBLDNS       = 'RBL/DNS';
my $CATEXECUT       = 'Execut.';
my $CATNONCONF      = 'Non.Conf.';
my $CATBADCOUNTRIES = 'Geoip.';
my $CATKARMA        = "Karma";

my $CATSPAMDEL = 'Del.Spam';
my $CATSPAM    = 'Qued.Spam?';
my $CATHAM     = 'Ham';
my $CATTOTALS  = 'Totals';
my $CATPERCENT = 'Percent';
my $CATDMARC   = "DMARC-Rej.";
my $CATLOAD    = "Rej.Load";
my @categs     = (
    $CATHOUR,   $CATFETCHMAIL, $CATWEBMAIL,      $CATMAILMAN,
    $CATLOCAL,  $CATRELAY,     $CATDMARC,        $CATVIRUS,
    $CATRBLDNS, $CATEXECUT,    $CATBADCOUNTRIES, $CATNONCONF,
    $CATLOAD,   $CATKARMA,     $CATSPAMDEL,      $CATSPAM,
    $CATHAM,    $CATTOTALS,    $CATPERCENT
);
my $GRANDTOTAL = '99';    #subs for count arrays, for grand total
my $PERCENT    = '98';    # for column percentages

my $categlen = @categs - 2;    #-2 to avoid the total and percent column

#
# Index for certain columns - should not move if we add columns
#
my %categindex;
@categindex{@categs} = ( 0 .. $#categs );
my $BadCountryCateg = $categindex{$CATBADCOUNTRIES};
my $DMARCcateg      = $categindex{$CATDMARC};          #Not used.
my $KarmaCateg      = $categindex{$CATKARMA};

my $above15            = 0;
my $RBLcount           = 0;
my $MiscDenyCount      = 0;
my $PatternFilterCount = 0;
my $noninfectedcount   = 0;
my $okemailcount       = 0;
my $infectedcount      = 0;
my $warnnoreject       = " ";
my $rblnotset          = ' ';

my %found_countries = ();
my $total_countries = 0;
my $BadCountries    = "";    #From the DB

my $FS = "\t";               # field separator used by logterse plugin
my %log_items = ( "", "", "", "", "", "", "", "" );
my $score;
my %timestamp_items = ();
my $localflag       = 0;     #indicate if current email is local or not
my $WebMailflag     = 0;     #indicate if current mail is send from webmail

# some storage for by recipient domains stats (PS)
# my bad : I have to deal with multiple simoultaneous connections
# will play with the process number.
# my $currentrcptdomain = '' ;
my %currentrcptdomain
  ;    # temporay store the recipient domain until end of mail processing
my %byrcptdomain;    # Store 'by domains stats'
my @extdomain
  ;    # only useful in some MX-Backup case, when any subdomains are allowed
my $morethanonercpt = 0;    # count every 'second' recipients for a mail.
my $recipcount      = 0;    # count every recipient email address received.

#
#Load up the emails currently stored for DMARC reporting - so that we can spot the reports being sent.
#Held in an slqite db, created by the DMARC perl lib.
#
my $dsn = "dbi:SQLite:dbname=/var/lib/qpsmtpd/dmarc/reports.sqlite"
  ;                         #Taken from /etc/mail-dmarc.ini

# doesn't seem to need
my $user                = "";
my $pass                = "";
my $DMARC_Report_emails = "";    #Flat string of all email addresses

#HTML Template containers for data
my $topbits;
my $stats_caption = "";
my $stats_table;
my $recip_table;
my $recip_caption = "";
my $virus_caption = "";
my $virus_table;
my $qpsmtpd_caption = "";
my $qpsmtpd_table;
my $geoip_caption = "";
my $geoip_table;
my $junkmail_caption = "";
my $junkmail_table;
my $blacklistsettings_caption = "";
my $blacklistsettings_table;
my $blacklistuse_caption = "";
my $blacklistuse_table;
my $emails_caption = "";
my $emails_table;
my $bottombit = "";

my $sendmsg;    #Used for wh_log to email log.

my $dateid;
my $servername =
    esmith::ConfigDB->open_ro->get('SystemName')->value . "."
  . esmith::ConfigDB->open_ro->get('DomainName')->value;

if ( my $dbix = DBIx::Simple->connect( $dsn, $user, $pass ) ) {
    my $result = $dbix->query("select rua from report_policy_published;");
    $result->bind( my ($emailaddress) );
    while ( $result->fetch ) {

#remember email from logterse entry has chevrons round it - so we add them here to guarantee the alighment of the match
#Remove the mailto:
        $emailaddress =~ s/mailto://g;

        # and map any commas to ><
        $emailaddress =~ s/,/></g;
        $DMARC_Report_emails .= "<" . $emailaddress . ">\n";
    }
    $dbix->disconnect();
}
else { $DMARC_Report_emails = "None found - DB not opened" }

# and setup list of local domains for spotting the local one in a list of email addresses (Remote station processing)
use esmith::DomainsDB;
my $d          = esmith::DomainsDB->open_ro();
my @domains    = $d->keys();
my $alldomains = "(";
foreach my $dom (@domains) { $alldomains .= $dom . "|" }
$alldomains .= ")";

# Saving the Log lines processed
my %LogLines     = ();   #Save all the log lines processed for writing to the DB
my $CurrentLogId = "";
my $Sequence     = 0;
my @LogIds       = ();   #One of each to see if it is unique

# store the domain of interest. Every other records are stored in a 'Other' zone
my $ddb = esmith::DomainsDB->open_ro or die "Couldn't open DomainsDB : $!\n";

foreach my $domain ( $ddb->get_all_by_prop( type => "domain" ) ) {
    $byrcptdomain{ $domain->key }{'type'} = 'local';
}
$byrcptdomain{ $cdb->get('SystemName')->value . "."
      . $cdb->get('DomainName')->value }{'type'} = 'local';

# is this system a MX-Backup ?
if ( $cdb->get('mxbackup') ) {
    if ( ( $cdb->get('mxbackup')->prop('status') || 'disabled' ) eq 'enabled' )
    {
        my %MXValues =
          split( /,/, ( $cdb->get('mxbackup')->prop('name') || '' ) );
        foreach my $data ( keys %MXValues ) {
            $byrcptdomain{$data}{'type'} = "mxbackup-$MXValues{ $data }";
            if ( $MXValues{$data} == 1 )
            {    # subdomains allowed, must take care of this
                push @extdomain, $data;
            }
        }
    }
}

my ( $start, $end ) = analysis_period();

#
# First check current configuration for logging, DNS enable and Max threshold for spamassassin
#

my $LogLevel     = $cdb->get('qpsmtpd')->prop('LogLevel');
my $HighLogLevel = ( $LogLevel > 6 );

my $RHSenabled = ( $cdb->get('qpsmtpd')->prop('RHSBL') eq 'enabled' );
my $DNSenabled = ( $cdb->get('qpsmtpd')->prop('DNSBL') eq 'enabled' );
my $SARejectLevel = $cdb->get('spamassassin')->prop('RejectLevel');
my $SATagLevel    = $cdb->get('spamassassin')->prop('TagLevel');
my $DomainName    = $cdb->get('DomainName')->value;

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
my $enableblacklist;    #Enabled according to setting in qpsmtpd
my $daysKeepLogData;
if ( $cdb->get('mailstats') ) {
    $enableqpsmtpdcodes =
      ( $cdb->get('mailstats')->prop("QpsmtpdCodes") || "enabled" ) eq "enabled"
      || $false;
    $enableSARules =
      ( $cdb->get('mailstats')->prop("SARules") || "enabled" ) eq "enabled"
      || $false;
    $enablejunkMailList =
      ( $cdb->get('mailstats')->prop("JunkMailList") || "enabled" ) eq "enabled"
      || $false;
    $enableGeoiptable =
      ( $cdb->get('mailstats')->prop("Geoiptable") || "enabled" ) eq "enabled"
      || $false;
    $savedata =
      ( $cdb->get('mailstats')->prop("SaveDataToMySQL") || "no" ) eq "yes"
      || $false;
    $daysKeepLogData =
      ( $cdb->get('mailstats')->prop("daysKeepLogData") || 30 );
}
else {
    $enableqpsmtpdcodes = $true;
    $enableSARules      = $true;
    $enablejunkMailList = $true;
    $enableGeoiptable   = $true;
    $savedata           = $false;
    $daysKeepLogData    = 30;
}
$enableblacklist =
     ( $cdb->get('qpsmtpd')->prop("RHSBL") || "disabled" ) eq "enabled"
  || ( $cdb->get('qpsmtpd')->prop("URIBL") || "disabled" ) eq "enabled";

my $makeHTMLemail = "no";
if ( $cdb->get('mailstats') ) {
    $makeHTMLemail = $cdb->get('mailstats')->prop('HTMLEmail') || "no";
}
my $makeHTMLpage = "no";
if ( $makeHTMLemail eq "yes" || $makeHTMLemail eq "both" ) {
    $makeHTMLpage = "yes";
}
if ( $cdb->get('mailstats') ) {
    $makeHTMLpage = $cdb->get('mailstats')->prop('HTMLPage') || "no";
}

# Init the hashes
my $nhour = floor( $start / 3600 );
my $ncateg;
my $count_id_index =
  0;    #Unique count_id - might need to be setup a unique start.
while ( $nhour < $end / 3600 ) {
    $counts{$nhour}   = ();
    $count_id{$nhour} = ();
    $ncateg           = 0;
    while ( $ncateg < @categs ) {
        $counts{$nhour}{ $categs[ $ncateg - 1 ] }   = 0;
        $count_id{$nhour}{ $categs[ $ncateg - 1 ] } = $count_id_index;
        $ncateg++;
        $count_id_index++;
    }
    $nhour++;
}

# and grand totals, percent and display status from db entries, and column widths
$ncateg = 0;
my $colpadding = 0;
while ( $ncateg < @categs ) {
    $counts{$GRANDTOTAL}{ $categs[$ncateg] } = 0;
    $count_id{$GRANDTOTAL}{ $categs[ $ncateg - 1 ] } = $count_id_index;
    $count_id_index++;

    $counts{$PERCENT}{ $categs[$ncateg] } = 0;
    if ( $cdb->get('mailstats') ) {
        $display[$ncateg] =
          lc( $cdb->get('mailstats')->prop( $categs[$ncateg] ) ) || "auto";
    }
    else {
        $display[$ncateg] = 'auto';
    }
    if ( $ncateg == 0 ) {
        $colwidth[$ncateg] = $HourColWidth + $colpadding;
    }
    else {
        $colwidth[$ncateg] = length( $categs[$ncateg] ) + 1 + $colpadding;
    }
    if ( $colwidth[$ncateg] < $MinCol ) {
        $colwidth[$ncateg] = $MinCol + $colpadding;
    }
    $ncateg++;
}

#Work out how many days before to delete logdata
# Needs "yum install perl-Time-Piece" (will make it a dependencies in the rpm)
#use Time::Piece;
#use Time::Seconds;
my $ONE_DAY = 3600 * 24;
my $firstDay =
  strftime( "%F", localtime( $start - $daysKeepLogData * $ONE_DAY ) );

# and get time and date interval for report
my $starttai    = Time::TAI64::unixtai64n($start);
my $endtai      = Time::TAI64::unixtai64n($end);
my $sum_SARules = 0;

# we remove non valid files
my @ARGV2;
foreach ( map { glob } @ARGV ) {
    push( @ARGV2, ($_) );
}
@ARGV = @ARGV2;

my $count = -1;    #for loop reduction in debugging mode

#
#---------------------------------------
# Scan the qpsmtpd log file(s)
#---------------------------------------

my $CurrentMailId = "";

LINE: while (<>) {

    next LINE if !( my ( $tai, $log ) = split( ' ', $_, 2 ) );

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
        my $l      = length($CurrentLine);
        my $Unique = 0;
        if ( $l != 0 ) {
            if ( defined($2) ) {
                if ( $2 ne $CurrentMailId ) {
                    print "CL:$CurrentLine*\n" if !defined($1);
                    $CurrentLogId  = $1 . "-" . $2;
                    $CurrentMailId = $2;
                    $Sequence      = 0;

                    #Now see if the MailId has been used already
                    my $CheckMailId = $CurrentMailId . ":" . $Unique;

                    #And then save it for next time it changes
                    push( @LogIds, $CurrentMailId . ":" . $Unique );
                }
                else { $Sequence++; }
                $LogLines{ $CurrentLogId . ":" . $Unique . ":" . $Sequence } =
                  $_;
            }
        }
    }

# pull out spamasassin rule lists - taken out 'cos qpsmtd>0.96 no longer logging detailed spam rule hits
    if ( $_ =~ m/spamassassin: pass, Ham,(.*)</ ) {

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
    if ( $_ =~ m/check_badcountries: GeoIP Country: (.*)/ ) {
        $found_countries{$1}++;
        $total_countries++;
    }

    #Pull out DMARC approvals
    if ( $_ =~ m/.*$DMARCOkPattern.*/ ) {
        $DMARCOkCount++;
    }

    #only select Logterse output
    next LINE unless m/logging::logterse:/;

    my $abstime = Time::TAI64::tai2unix($tai);
    my $abshour = floor( $abstime / 3600 );      # Hours since the epoch

    my ( $timestamp_part, $log_part ) = split( '`', $_, 2 );    #bjr 0.6.12
    my (@log_items) = split $FS, $log_part;

    my (@timestamp_items) = split( ' ', $timestamp_part );

    my $result = "rejected";    #Tag as rejected unti we know otherwise
        # we store the more recent recipient domain, for domain statistics
        # in fact, we only store the first recipient. Could be sort of headhache
        # to obtain precise stats with many recipients on more than one domain !
    my $proc     = $timestamp_items[1];    #numeric Id for the email
    my $emailnum = $proc;                  #proc gets modified later...

    $totalexamined++;

    # first spot the fetchmail and local deliveries.
    # Spot from local workstation
    $localflag   = 0;
    $WebMailflag = 0;
    if ( $log_items[1] =~ m/$DomainName/ ) {    #bjr
        $localsendtotal++;
        $counts{$abshour}{$CATLOCAL}++;
        push_count_ids( $CurrentMailId, $abshour, $CATLOCAL );
        $localflag = 1;
    }

    #Or a remote station
    elsif ( ( !test_for_private_ip( $log_items[0] ) )
        and ( test_for_private_ip( $log_items[2] ) )
        and ( $log_items[5] eq "queued" ) )
    {

        #Remote user
        $localflag = 1;
        $counts{$abshour}{$CATRELAY}++;
        push_count_ids( $CurrentMailId, $abshour, $CATRELAY );
    }

    elsif ( ( $log_items[2] =~ m/$WebmailIP/ )
        and ( !test_for_private_ip( $log_items[0] ) ) )
    {

        #Webmail
        $localflag = 1;
        $WebMailsendtotal++;
        $counts{$abshour}{$CATWEBMAIL}++;
        push_count_ids( $CurrentMailId, $abshour, $CATWEBMAIL );
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
                push_count_ids( $CurrentMailId, $abshour, $CATMAILMAN );

                $localflag = 1;
            }
            else {

                #Or sent to the DMARC server
                #check for email address in $DMARC_Report_emails string
                my $logemail = $log_items[4];
                if (   ( index( $DMARC_Report_emails, $logemail ) >= 0 )
                    or ( $logemail =~ m/$DMARCDomain/ ) )
                {
                    $localsendtotal++;
                    $DMARCSendCount++;
                    $localflag = 1;
                }
                else {
                    if ( exists $log_items[8] ) {

                        # ignore incoming localhost spoofs
                        if ( $log_items[8] =~ m/msg denied before queued/ ) { }
                        else {

                            #Webmail
                            $localflag = 1;
                            $WebMailsendtotal++;
                            $counts{$abshour}{$CATWEBMAIL}++;
                            push_count_ids( $CurrentMailId, $abshour,
                                $CATWEBMAIL );
                            $WebMailflag = 1;
                        }
                    }
                    else {
                        $localflag = 1;
                        $WebMailsendtotal++;
                        $counts{$abshour}{$CATWEBMAIL}++;
                        push_count_ids( $CurrentMailId, $abshour, $CATWEBMAIL );
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
        push_count_ids( $CurrentMailId, $abshour, $CATFETCHMAIL );

    }
    elsif ( $log_items[3] =~ m/$FETCHMAIL/ ) {
        $localAccepttotal++;
        $counts{$abshour}{$CATFETCHMAIL}++;
        push_count_ids( $CurrentMailId, $abshour, $CATFETCHMAIL );
    }

# and adjust for recipient field if not set-up by denying plugin - extract from deny msg

    if ( length( $log_items[4] ) == 0 ) {
        if ( $log_items[5] eq 'check_goodrcptto' ) {
            if ( $log_items[7] gt "invalid recipient" ) {
                $log_items[4] =
                  substr( $log_items[7], 18 );    #Leave only email address

            }
        }
    }

    # reduce to lc and process each e,mail if a list, pseperatedy commas
    my $recipientmail = lc( $log_items[4] );
    if ( $recipientmail =~ m/.*,/ ) {

        #comma - split the line and deal with each domain
        #              print $recipientmail."\n";
        my ($recipients) = split( ',', $recipientmail );
        foreach my $recip ($recipients) {
            $proc = $proc . $recip;
            $currentrcptdomain{$proc} = $recip;
            add_in_domain($proc);
            $recipcount++;
        }
    }
    else {
        $proc = $proc . $recipientmail;
        $currentrcptdomain{$proc} = $recipientmail;
        add_in_domain($proc);
        $recipcount++;
    }

    # then categorise the result
    if ( exists $log_items[5] ) {

        if ( $log_items[5] eq 'naughty' ) {
            my $rejreason = $log_items[7];
            $rejreason = /.*(\(.*\)).*/;
            if   ( !defined($1) ) { $rejreason = "unknown" }
            else                  { $rejreason = $1 }
            $found_qpcodes{ $log_items[5] . "-" . $rejreason }++;
        }
        else {
            $found_qpcodes{ $log_items[5] }++;
        }    ##Count different qpsmtpd result codes

        if ( $log_items[5] eq 'check_earlytalker' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_relay' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_norelay' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'require_resolvable_fromhost' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_basicheaders' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'rhsbl' ) {
            $RBLcount++;
            $counts{$abshour}{$CATRBLDNS}++;
            push_count_ids( $CurrentMailId, $abshour, $CATRBLDNS );
            mark_domain_rejected($proc);
            $blacklistURL{ get_domain( $log_items[7] ) }++;
        }

        elsif ( $log_items[5] eq 'dnsbl' ) {
            $RBLcount++;
            $counts{$abshour}{$CATRBLDNS}++;
            push_count_ids( $CurrentMailId, $abshour, $CATRBLDNS );
            mark_domain_rejected($proc);
            $blacklistURL{ get_domain( $log_items[7] ) }++;
        }

        elsif ( $log_items[5] eq 'check_badmailfrom' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_badrcptto_patterns' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_badrcptto' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_spamhelo' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_goodrcptto extn' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'rcpt_ok' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'pattern_filter' ) {
            $PatternFilterCount++;
            $counts{$abshour}{$CATEXECUT}++;
            push_count_ids( $CurrentMailId, $abshour, $CATEXECUT );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'virus::pattern_filter' ) {
            $PatternFilterCount++;
            $counts{$abshour}{$CATEXECUT}++;
            push_count_ids( $CurrentMailId, $abshour, $CATEXECUT );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_goodrcptto' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_smtp_forward' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'count_unrecognized_commands' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_badcountries' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATBADCOUNTRIES}++;
            push_count_ids( $CurrentMailId, $abshour, $CATBADCOUNTRIES );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'tnef2mime' ) { }    #Not expecting this one.

        elsif ( $log_items[5] eq 'spamassassin' ) {
            $above15++;
            $counts{$abshour}{$CATSPAMDEL}++;
            push_count_ids( $CurrentMailId, $abshour, $CATSPAMDEL );

            # and extract the spam score
            if ( $log_items[8] =~ "Yes, score=(.*) required=([0-9\.]+)" ) {
                $rejectspamavg += $1;
            }
            mark_domain_rejected($proc);
        }

        elsif (( $log_items[5] eq 'virus::clamav' )
            or ( $log_items[5] eq 'virus::clamdscan' ) )
        {
            $infectedcount++;
            $counts{$abshour}{$CATVIRUS}++;
            push_count_ids( $CurrentMailId, $abshour, $CATVIRUS );

            #extract the virus name
            if ( $log_items[7] =~ "Virus found: (.*)" ) {
                $found_viruses{$1}++;
            }
            else { $found_viruses{ $log_items[7] }++ }    #Some other message!!
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'queued' ) {
            $Accepttotal++;

           #extract the spam score
           # Remove count for rejectred as it looks as if it might get through!!
            $result = "queued";
            if ( $log_items[8] =~
                ".*score=([+-]?\\d+\.?\\d*).* required=([0-9\.]+)" )
            {
                $score = trim($1);
                if ( $score =~ /^[+-]?\d+\.?\d*$/ )    #check its numeric
                {
                    if ( $score < $SATagLevel ) {
                        $hamcount++;
                        $counts{$abshour}{$CATHAM}++;
                        push_count_ids( $CurrentMailId, $abshour, $CATHAM );
                        $hamavg += $score;
                    }
                    else {
                        $spamcount++;
                        $counts{$abshour}{$CATSPAM}++;
                        push_count_ids( $CurrentMailId, $abshour, $CATSPAM );
                        $spamavg += $score;
                        $result = "spam";
                    }
                }
                else {
                    print "Unexpected non numeric found in $proc:"
                      . $log_items[8]
                      . "($score)\n";
                }
            }
            else {

                # no SA score - treat it as ham
                $hamcount++;
                $counts{$abshour}{$CATHAM}++;
                push_count_ids( $CurrentMailId, $abshour, $CATHAM );

            }
            if ( ( $currentrcptdomain{$proc} || '' ) ne '' ) {
                $byrcptdomain{ $currentrcptdomain{$proc} }{'accept'}++;
                $currentrcptdomain{$proc} = '';
            }
        }

        elsif ( $log_items[5] eq 'tls' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'auth::auth_cvm_unix_local' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'earlytalker' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'uribl' ) {
            $RBLcount++;
            $counts{$abshour}{$CATRBLDNS}++;
            push_count_ids( $CurrentMailId, $abshour, $CATRBLDNS );
            mark_domain_rejected($proc);
            $blacklistURL{ get_domain( $log_items[7] ) }++;
        }

        elsif ( $log_items[5] eq 'naughty' ) {

#Naughty plugin seems to span a number of rejection reasons - so we have to use the next but one log_item[7] to identify
            if ( $log_items[7] =~ m/(karma)/ ) {
                $MiscDenyCount++;
                $counts{$abshour}{$CATKARMA}++;
                push_count_ids( $CurrentMailId, $abshour, $CATKARMA );
                mark_domain_rejected($proc);
            }
            elsif ( $log_items[7] =~ m/(dnsbl)/ ) {
                $RBLcount++;
                $counts{$abshour}{$CATRBLDNS}++;
                push_count_ids( $CurrentMailId, $abshour, $CATRBLDNS );
                mark_domain_rejected($proc);
                $blacklistURL{ get_domain( $log_items[7] ) }++;
            }
            elsif ( $log_items[7] =~ m/(helo)/ ) {
                $MiscDenyCount++;
                $counts{$abshour}{$CATNONCONF}++;
                push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
                mark_domain_rejected($proc);
            }
            else {

                #Unidentified Naughty rejection
                $MiscDenyCount++;
                $counts{$abshour}{$CATNONCONF}++;
                push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
                mark_domain_rejected($proc);
                $unrecog_plugin{ $log_items[5] . "-" . $log_items[7] }++;
            }
        }
        elsif ( $log_items[5] eq 'resolvable_fromhost' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'loadcheck' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATLOAD}++;
            push_count_ids( $CurrentMailId, $abshour, $CATLOAD );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'karma' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATKARMA}++;
            push_count_ids( $CurrentMailId, $abshour, $CATKARMA );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'dmarc' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATDMARC}++;
            push_count_ids( $CurrentMailId, $abshour, $CATDMARC );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'relay' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'headers' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'mailfrom' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'badrcptto' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'helo' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'check_smtp_forward' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        elsif ( $log_items[5] eq 'sender_permitted_from' ) {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
        }

        #Treat it as Unconf if not recognised
        else {
            $MiscDenyCount++;
            $counts{$abshour}{$CATNONCONF}++;
            push_count_ids( $CurrentMailId, $abshour, $CATNONCONF );
            mark_domain_rejected($proc);
            $unrecog_plugin{ $log_items[5] }++;
        }
    }    #Log[5] exists

    #Entry if not local send
    if ( $localflag == 0 ) {
        if ( length( $log_items[4] ) > 0 ) {

            # Need to check here for multiple email addresses
            my @emails = split( ",", lc( $log_items[4] ) );
            if ( scalar(@emails) > 1 ) {

#Just pick the first local address to hang it on.
# TEMP - just go for the first address until I can work out how to spot the 1st "local" one
                $usercounts{ $emails[0] }{$result}++;
                $usercounts{ $emails[0] }{"proc"} = $proc;

                #Compare with @domains array until we get a local one
                my $gotone = $false;
                foreach my $email (@emails) {

                    #Extract the domain from the email address
                    my $fullemail = $email;
                    $email = s/.*\@(.*)$/$1/;

                    #and see if it is local
                    if ( $email =~ m/$alldomains/ ) {
                        $usercounts{ lc($fullemail) }{$result}++;
                        $usercounts{ lc($fullemail) }{"proc"} = $proc;
                        $gotone = $true;
                        last;
                    }
                }
                if ( !$gotone ) {
                    $usercounts{'No internal email $proc'}{$result}++;
                    $usercounts{'No internal email $proc'}{"proc"} = $proc;
                }

            }
            else {
                $usercounts{ lc( $log_items[4] ) }{$result}++;
                $usercounts{ lc( $log_items[4] ) }{"proc"} = $proc;
            }
        }
    }

    #exit if $emailnum == 15858;

}    #END OF MAIN LOOP

ENDOFLOOP:

#total up grand total Columns
$nhour = floor( $start / 3600 );
while ( $nhour < $end / 3600 ) {
    $ncateg = 0;    #past the where it came from columns
    while ( $ncateg < @categs ) {

        #total columns
        $counts{$GRANDTOTAL}{ $categs[$ncateg] } +=
          $counts{$nhour}{ $categs[$ncateg] };

        # and total rows
        if ( $ncateg < $categlen and $ncateg >= $countfromhere )
        {           #skip initial columns of non final reasons
            $counts{$nhour}{ $categs[ @categs - 2 ] } +=
              $counts{$nhour}{ $categs[$ncateg] };
        }
        $ncateg++;
    }

    $nhour++;
}

#Compute row totals and row percentages
$nhour = floor( $start / 3600 );
while ( $nhour < $end / 3600 ) {
    $counts{$nhour}{ $categs[ @categs - 1 ] } =
      $counts{$nhour}{ $categs[ @categs - 2 ] } * 100 / $totalexamined
      if $totalexamined;
    $nhour++;

}

#compute column percentages
$ncateg = 0;
while ( $ncateg < @categs ) {
    if ( $ncateg == @categs - 1 ) {
        $counts{$PERCENT}{ $categs[$ncateg] } =
          $counts{$GRANDTOTAL}{ $categs[ $ncateg - 1 ] } * 100 / $totalexamined
          if $totalexamined;
    }
    else {
        $counts{$PERCENT}{ $categs[$ncateg] } =
          $counts{$GRANDTOTAL}{ $categs[$ncateg] } * 100 / $totalexamined
          if $totalexamined;
    }
    $ncateg++;
}

#compute sum of row percentages
$nhour = floor( $start / 3600 );
while ( $nhour < $end / 3600 ) {
    $counts{$GRANDTOTAL}{ $categs[ @categs - 1 ] } +=
      $counts{$nhour}{ $categs[ @categs - 1 ] };
    $nhour++;

}

my $QueryNoLogTerse = ( $totalexamined == 0 )
  ;    #might indicate logterse not installed in qpsmtpd plugins

#Calculate some numbers

$spamavg       = $spamavg / $spamcount     if $spamcount;
$rejectspamavg = $rejectspamavg / $above15 if $above15;
$hamavg        = $hamavg / $hamcount       if $hamcount;

#  RBL etc percent of total SMTP sessions

my $rblpercent = ( ( $RBLcount / $totalexamined ) * 100 ) if $totalexamined;
my $PatternFilterpercent = ( ( $PatternFilterCount / $totalexamined ) * 100 )
  if $totalexamined;
my $Miscpercent = ( ( $MiscDenyCount / $totalexamined ) * 100 )
  if $totalexamined;

#Spam and virus percent of total email downloaded
#Expressed as a % of total examined
my $spampercent = ( ( $spamcount / $totalexamined ) * 100 ) if $totalexamined;
my $hampercent  = ( ( $hamcount / $totalexamined ) * 100 )  if $totalexamined;
my $hrsinperiod = ( ( $end - $start ) / 3600 );
my $emailperhour   = ( $totalexamined / $hrsinperiod )   if $totalexamined;
my $above15percent = ( $above15 / $totalexamined * 100 ) if $totalexamined;
my $infectedpercent = ( ( $infectedcount / ($totalexamined) ) * 100 )
  if $totalexamined;
my $AcceptPercent = ( ( $Accepttotal / ($totalexamined) ) * 100 )
  if $totalexamined;

my $oldFH;

#Open Sendmail if we are mailing it
if ( $opt{'mail'} and !$disabled ) {
    open( SENDMAIL, "|$opt{'sendmail'} -oi -t -odq" )
      or die "Can't open sendmail: $!\n";
    print SENDMAIL "From: $opt{'from'}\n";
    print SENDMAIL "To: $opt{'mail'}\n";
    print SENDMAIL "Subject: Spam Filter Statistics from $hostname - ",
      strftime( "%F", localtime($start) ), "\n\n";
    $oldFH = select SENDMAIL;
}

my $telapsed = time - $tstart;

if ( !$disabled ) {

    #Output results

# NEW - save the print to a variable so that it can be processed into html.
#
#Save current output selection and divert into variable
#
# Build up array of hashrefs for HTML template processing and print to the text email at the end.
#
    my $output;
    my $tablestr = "";
    my $topbit;
    open( my $outputFH, '>', \$tablestr ) or die;    # This shouldn't fail
    my $oldFH = select $outputFH;

    my $todaydate = strftime( "%F", localtime($start) );

    #die("Start:".$start);
    my $yesterdaydate = strftime( "%F", localtime( $start - 3600 * 24 ) );
    my $tomorrowdate  = strftime( "%F", localtime( $start + 3600 * 24 ) );

    print "*SMEServer daily email statistics from $hostname - "
      . $todaydate . "*\n";
    print
"----------------------------------------------------------------------------------",
      "\n\n";
    my $version = "$0 Version : $opt{'version'}";
    push( @{$topbit}, { f1 => "$version\n" } );
    push( @{$topbit}, { f1 => "Params : ".$opt{'params'}."\n"} );
    push(
        @{$topbit},
        {
            f1 => "Period Beginning : "
              . strftime( "%c", localtime($start) ) . "\n"
        }
    );
    push(
        @{$topbit},
        {
            f1 => "Period Ending    : "
              . strftime( "%c", localtime($end) ) . "\n"
        }
    );
    push(
        @{$topbit},
        { f1 => "Clam Version/DB Count/Last DB update: " . `freshclam -V` }
    );
    push( @{$topbit}, { f1 => "SpamAssassin Version : " . `spamassassin -V` } );
    push(
        @{$topbit},
        {
            f1 => sprintf(
                "Tag level: %3d; Reject level: %3d $warnnoreject\n",
                $SATagLevel, $SARejectLevel
            )
        }
    );

    if ($HighLogLevel) {
        push(
            @{$topbit},
            {
                f1 => sprintf(
                        "*Loglevel is set to: "
                      . $LogLevel
                      . " - you only need it set to 6\n"
                )
            }
        );
        push( @{$topbit}, { f1 => sprintf("\tYou can set it this way:\n") } );
        push(
            @{$topbit},
            { f1 => sprintf("\tconfig setprop qpsmtpd LogLevel 6\n") }
        );
        push( @{$topbit}, { f1 => sprintf("\tsignal-event email-update\n") } );
        push( @{$topbit}, { f1 => sprintf("\tsv t /var/service/qpsmtpd\n") } );
    }
    push(
        @{$topbit},
        { f1 => sprintf( "Reporting Period : %.2f hrs\n", $hrsinperiod ) }
    );
    push(
        @{$topbit},
        {
            f1 => sprintf( "All SMTP connections accepted:%8d          \n",
                $totalexamined )
        }
    );
    push(
        @{$topbit},
        {
            f1 => sprintf( "Emails per hour              : %8.1f/hr\n",
                $emailperhour || 0 )
        }
    );
    push(
        @{$topbit},
        {
            f1 => sprintf( "Average spam score (accepted): %11.2f\n",
                $spamavg || 0 )
        }
    );
    push(
        @{$topbit},
        {
            f1 => sprintf( "Average spam score (rejected): %11.2f\n",
                $rejectspamavg || 0 )
        }
    );
    push(
        @{$topbit},
        {
            f1 => sprintf(
                "Average ham score            : %11.2f\n", $hamavg || 0
            )
        }
    );
    push(
        @{$topbit},
        {
            f1 =>
              sprintf(
"Number of DMARC reporting emails sent:\t%11d (not shown on table)\n",
                $DMARCSendCount || 0 )
        }
    );

    if ( $hamcount != 0 ) {
        push(
            @{$topbit},
            {
                f1 => sprintf(
"Number of emails approved through DMARC:\t%11d (%3d%% of Ham count)\n",
                    $DMARCOkCount || 0,
                    $DMARCOkCount * 100 / $hamcount || 0
                )
            }
        );
    }

    my $smeoptimizerprog = "/usr/local/smeoptimizer/SMEOptimizer.pl";
    if ( -e $smeoptimizerprog ) {

        #smeoptimizer installed - get result of status
        my @smeoptimizerlines =
          split( /\n/, `/usr/local/smeoptimizer/SMEOptimizer.pl -status` );
        push( @{$topbit}, { f1 => "SMEOptimizer status:\n" } );
        push( @{$topbit}, { f1 => "\t" . $smeoptimizerlines[6] . "\n" } );
        push( @{$topbit}, { f1 => "\t" . $smeoptimizerlines[7] . "\n" } );
        push( @{$topbit}, { f1 => "\t" . $smeoptimizerlines[8] . "\n" } );
        push( @{$topbit}, { f1 => "\t" . $smeoptimizerlines[9] . "\n" } );
        push( @{$topbit}, { f1 => "\t" . $smeoptimizerlines[10] . "\n" } );
    }

    #Print them for the text email
    foreach my $str (@$topbit) {
        print $$str{"f1"};
    }

    $stats_caption = "\nStatistics by Hour:\n";
    print $stats_caption;

    #
    # start by working out which colunns to show - tag the display array
    #
    $ncateg = 1;                ##skip the first column
    $finaldisplay[0] = $true;
    while ( $ncateg < $categlen ) {
        if    ( $display[$ncateg] eq 'yes' ) { $finaldisplay[$ncateg] = $true }
        elsif ( $display[$ncateg] eq 'no' )  { $finaldisplay[$ncateg] = $false }
        else {
            $finaldisplay[$ncateg] =
              ( $counts{$GRANDTOTAL}{ $categs[$ncateg] } != 0 );
            if ( $finaldisplay[$ncateg] ) {

             #if it has been non zero and auto, then make it yes for the future.
                esmith::ConfigDB->open->get('mailstats')
                  ->set_prop( $categs[$ncateg], 'yes' );
            }

        }
        $ncateg++;
    }

    #make sure total and percentages are shown
    $finaldisplay[ @categs - 2 ] = $true;
    $finaldisplay[ @categs - 1 ] = $true;

    # and put together the print lines

    my $Line1;      #Full Line across the page
    my $Line2;      #Broken Line across the page
    my $Titles;     #Column headers
    my $Values;     #Values
    my $Totals;     #Corresponding totals
    my $Percent;    # and column percentages

    my $hour = floor( $start / 3600 );
    $Line1   = '';
    $Line2   = '';
    $Titles  = '';
    $Values  = '';
    $Totals  = '';
    $Percent = '';
    my $stats_table;

    while ( $hour <= $end / 3600 ) {
        my $stats_table_cols_titles, my $value, my $title, my $percent;
        if ( $hour == floor( $start / 3600 ) ) {

            #Do initial lines
            $ncateg = 0;
            while ( $ncateg < @categs ) {
                if ( $finaldisplay[$ncateg] ) {
                    $Line1 .=
                      substr( '---------------------', 0, $colwidth[$ncateg] );
                    $Line2 .=
                      substr( '---------------------', 0,
                        $colwidth[$ncateg] - 1 );
                    $Line2 .= " ";
                    $title = sprintf(
                        '%' . ( $colwidth[$ncateg] - 1 ) . 's',
                        $categs[$ncateg]
                    );
                    $Titles .= $title . "|";
                    push( @{$stats_table_cols_titles}, { col => $title } );
                }
                $ncateg++;
            }
            push( @{$stats_table}, { cols => $stats_table_cols_titles } );
        }

        my $stats_table_cols;
        $ncateg = 0;
        if ( $hour < $end / 3600 ) {
            while ( $ncateg < @categs ) {
                if ( $finaldisplay[$ncateg] ) {
                    if ( $ncateg == 0 ) {
                        $value =
                          strftime( "%F, %H", localtime( $hour * 3600 ) ) . " ";
                    }
                    elsif ( $ncateg == @categs - 1 ) {

                        #percentages in last column
                        $value = sprintf(
                            '%' . ( $colwidth[$ncateg] - 2 ) . '.1f',
                            $counts{$hour}{ $categs[$ncateg] }
                        ) . "%";
                    }
                    else {

                        #body numbers
                        $value = sprintf(
                            '%' . ( $colwidth[$ncateg] - 1 ) . 'd',
                            $counts{$hour}{ $categs[$ncateg] }
                        ) . " ";
                    }
                    if ( ( $ncateg == @categs - 1 ) ) {
                        $value = $value . "\n";
                    }    #&& ($hour == floor($end / 3600)-1)
                    push(
                        @{$stats_table_cols},
                        {
                            hour  => $hour,
                            categ => $categs[$ncateg],
                            col   => trim($value),
                            id    => $count_id{$hour}{ $categs[$ncateg] }
                        }
                    );
                    $Values .= $value;
                }
                $ncateg++;
            }
            push( @{$stats_table}, { cols => $stats_table_cols } );

        }
        my $stats_table_cols_totals;
        push( @{$stats_table_cols_totals}, { col => "Totals", id => 0 } );
        if ( $hour == floor( $end / 3600 ) ) {

            #Do the total line
            $ncateg = 0;
            while ( $ncateg < @categs ) {
                if ( $finaldisplay[$ncateg] ) {
                    if ( $ncateg == 0 ) {
                        $Totals .=
                          substr( 'Totals                                   ',
                            0, $colwidth[$ncateg] - 2 );

#$Percent .= substr('PERCENTAGES                              ',0,$colwidth[$ncateg]-1);
                    }
                    else {

           # identify bottom right group and supress unless db->ShowGranPerc set
                        if ( $ncateg == @categs - 1 ) {
                            $total = sprintf(
                                '%' . $colwidth[$ncateg] . '.1f',
                                $counts{$GRANDTOTAL}{ $categs[$ncateg] }
                            ) . '%';
                        }
                        else {
                            $total = sprintf(
                                '%' . $colwidth[$ncateg] . 'd',
                                $counts{$GRANDTOTAL}{ $categs[$ncateg] }
                            );
                        }
                        $Totals .= $total;
                        push(
                            @{$stats_table_cols_totals},
                            {
                                col => trim($total),
                                id => $count_id{$GRANDTOTAL}{ $categs[$ncateg] }
                            }
                        );
                    }
                }
                $ncateg++;
            }
            push( @{$stats_table}, { cols => $stats_table_cols_totals } );

            my $stats_table_cols_percent;
            push( @{$stats_table_cols_percent}, { col => "Percentages" } );
            $ncateg = 0;
            while ( $ncateg < @categs ) {

                #and the percentages line
                if ( $finaldisplay[$ncateg] ) {
                    if ( $ncateg == 0 ) {

#$percent = substr('PERCENTAGES                              ',0,$colwidth[$ncateg]-1);
                    }
                    else {
                        $percent = sprintf(
                            '%' . ( $colwidth[$ncateg] - 1 ) . '.1f',
                            $counts{$PERCENT}{ $categs[$ncateg] }
                        ) . '%';
                        $Percent .= $percent;
                        push(
                            @{$stats_table_cols_percent},
                            { col => trim($percent) }
                        );
                    }

                }
                $ncateg++;
            }
            push( @{$stats_table}, { cols => $stats_table_cols_percent } );
        }

        #$ncateg = 0;
        $hour++;
    }

    #
    # print it.
    #

    print $Line1. "\n";
    print $Titles. "\n";
    print $Line2. "\n";
    print $Values;
    print $Line2. "\n";
    print $Totals. "\n";
    print $Percent. "\n";
    print $Line1. "\n";

    my $stats_footnote;
    if ( $localAccepttotal > 0 ) {
        push(
            @{$stats_footnote},
            {
                f1 =>
"*Fetchml* means connections from Fetchmail delivering email\n"
            }
        );
    }
    push(
        @{$stats_footnote},
        {
            f1 =>
              "*Local* means connections from workstations on local LAN.\n\n"
        }
    );
    push(
        @{$stats_footnote},
        {
            f1 =>
"*Non\.Conf\.* means sending mailserver did not conform to correct protocol"
        }
    );
    push(
        @{$stats_footnote},
        { f1 => "  or email was to non existant address.\n\n" }
    );
    if ( $finaldisplay[$KarmaCateg] ) {
        push(
            @{$stats_footnote},
            {
                f1 =>
"*Karma* means email was rejected based on the mailserver's previous activities.\n\n"
            }
        );
    }
    if ( $finaldisplay[$BadCountryCateg] or $total_countries > 0 ) {
        $BadCountries = $cdb->get('qpsmtpd')->prop('BadCountries') || "*none*";
        push(
            @{$stats_footnote},
            {
                f1 => "*Geoip\.*:Bad Countries mask is:"
                  . $BadCountries . "\n\n"
            }
        );
    }
    if ( scalar keys %unrecog_plugin > 0 ) {

        #Show unrecog plugins found
        push(
            @{$stats_footnote},
            { f1 => "*Unrecognised plugins found - categorised as Non-Conf\n" }
        );
        foreach my $unrec ( keys %unrecog_plugin ) {
            push(
                @{$stats_footnote},
                { f1 => "\t$unrec\t($unrecog_plugin{$unrec})\n" }
            );
        }
        push( @{$stats_footnote}, { f1 => "\n" } );
    }
    if ($QueryNoLogTerse) {
        push(
            @{$stats_footnote},
            {
                f1 =>
"* - as no records where found, it looks as though you may not have the *logterse* \nplugin running as part of qpsmtpd \n\n"
            }
        );

#      print " to enable it follow the instructions at .............................\n"});
    }
    if ( !$RHSenabled or !$DNSenabled ) {

        # comment about RBL not set
        push(
            @{$stats_footnote},
            {
                f1 =>
"* - This means that one or more of the possible spam black listing services\n    that are available have not been enabled.\n"
            }
        );
        push( @{$stats_footnote}, { f1 => " You have not enabled:\n" } );
        if ( !$RHSenabled ) {
            push( @{$stats_footnote}, { f1 => "    RHSBL\n" } );
        }
        if ( !$DNSenabled ) {
            push( @{$stats_footnote}, { f1 => "    DNSBL\n" } );
        }
        push(
            @{$stats_footnote},
            { f1 => " To enable these you can use the following commands:\n" }
        );
        if ( !$RHSenabled ) {
            push(
                @{$stats_footnote},
                { f1 => " config setprop qpsmtpd RHSBL enabled\n" }
            );
        }
        if ( !$DNSenabled ) {
            push(
                @{$stats_footnote},
                { f1 => " config setprop qpsmtpd DNSBL enabled\n" }
            );
        }

        # there so much templates to expand... (PS)
        push(
            @{$stats_footnote},
            {
                f1 =>
" Followed by:\n signal-event email-update and\n sv t /var/service/qpsmtpd\n\n"
            }
        );
    }

    #and print it for the email
    foreach my $str (@$stats_footnote) {
        print $$str{"f1"};
    }

    show_recip_usage();

  DISPLAYTABLES:

    if   ( $infectedcount > 0 ) { show_virus_variants(); }
    else                        { $virus_caption = ""; @{$virus_table} = {}; }

    if ($enableqpsmtpdcodes) { show_qpsmtpd_codes(); }
    else                     { $qpsmtpd_caption = ""; @{$qpsmtpd_table} = {}; }

    # no SARules in latest qpsmtpd
    #    if ($enableSARules) {show_SARules_codes();}
    #    else {@{$SARules_table}={};}
	#die($finaldisplay[$BadCountryCateg]);
	#die($total_countries);
	
    if ( $enableGeoiptable
        and ( ( $total_countries > 0 ) or $finaldisplay[$BadCountryCateg] ) )
    {
        show_Geoip_results();
    }
    else { $geoip_caption = ""; @{$geoip_table} = {}; }

    if ($enablejunkMailList) { List_Junkmail(); }
    else { $junkmail_caption = ""; @{$junkmail_table} = {}; }

    if ($enableblacklist) { show_blacklist_counts(); }
    else { $blacklistsettings_caption = ""; @{$blacklistsettings_table} = {}; }

    show_user_stats();

    $bottombit = "Report generated in $telapsed seconds on " . localtime();
    print $bottombit. "\n";

    if ($savedata) { save_data(); }
    else {
        print
"No data saved -  if you want to save data to a MySQL database, then please use:\n"
          . "config setprop mailstats SaveDataToMySQL yes\n";
    }

    #and do some maintenace of the local directory containg the html pages
    my $dir = '.';
    opendir( DIR, $dir ) or die $!;
    while ( my $file = readdir(DIR) ) {

        # We only want files
        next unless ( -f "$dir/$file" );

        # Use a regular expression to find files ending in .html
        next unless ( $file =~ m/\.html$/ );

        #Extract date from filename
        my $datestr = substr( $file, 1, 9 );
        if ( strtotime($datestr) < strtotime($firstDay) ) {

            #Before the limit - delete the file
            unlink($file);
        }
    }
    closedir(DIR);

    select $oldFH;
    close $outputFH;
    if ( $makeHTMLemail eq "no" or $makeHTMLemail eq "both" ) {
        print $tablestr;

        #Close Sendmail if it was opened
        if ( $opt{'mail'} ) {
            select $oldFH;
            close(SENDMAIL);
        }
    }
  HTML:
    if (   $makeHTMLemail eq "yes"
        or $makeHTMLemail eq "both"
        or $makeHTMLpage  eq "yes" )
    {
        require HTML::Template;

        # see front Comment about installing this....
        my $template = HTML::Template->new(
            filename          => 'mailstats.tmpl',
            loop_context_vars => 1,
            die_on_bad_params => 0,
            global_vars       => 1
        );
        my @params = {
            VERSION                   => $version,
            TODAYDATE                 => $todaydate,
            YESTERDAYDATE             => $yesterdaydate,
            TOMORROWDATE              => $tomorrowdate,
            HOSTNAME                  => $hostname,
            DOMAIN                    => $DomainName,
            SERVERNAME                => $servername,
            DATEID                    => $dateid,
            TOPBIT                    => $topbit,
            STATS_CAPTION             => $stats_caption,
            STATS_TABLE               => $stats_table,
            STATS_FOOTNOTE            => $stats_footnote,
            RECIP_CAPTION             => $recip_caption,
            RECIP_TABLE               => $recip_table,
            VIRUS_CAPTION             => $virus_caption,
            VIRUS_TABLE               => $virus_table,
            QPSMTPD_CAPTION           => $qpsmtpd_caption,
            QPSMTPD_TABLE             => $qpsmtpd_table,
            GEOIP_CAPTION             => $geoip_caption,
            GEOIP_TABLE               => $geoip_table,
            JUNKMAIL_CAPTION          => $junkmail_caption,
            JUNKMAIL_TABLE            => $junkmail_table,
            BLACKLISTSETTINGS_TABLE   => $blacklistsettings_table,
            BLACKLISTSETTINGS_CAPTION => $blacklistsettings_caption,
            BLACKLISTUSE_CAPTION      => $blacklistuse_caption,
            BLACKLISTUSE_TABLE        => $blacklistuse_table,
            EMAILS_CAPTION            => $emails_caption,
            EMAILS_TABLE              => $emails_table,
            BOTTOMBIT                 => $bottombit
        };
        $template->param(@params);
        my $html = $template->output;

        #edit out newlines and tabs in text
        $html =~ s/\t|\n//g;

   #and drop in newline on breaks and end of tables - makes it look a bit better
        $html =~ s/(<\/table>|<br \/>)/$1\n/g;
        if ( $makeHTMLpage eq "yes" ) {

            #And drop it into a file
            my $filename = $htmlpagepath . "mailstats$todaydate.html";
            open( my $fh, '>', $filename )
              or die "Could not open file '$filename' $!";
            print $fh $html;
            close $fh;
        }
        if ( $makeHTMLemail eq "yes" or $makeHTMLemail eq "both" ) {

            # create html email
            if ( $opt{'mail'} and !$disabled ) {

                #Add in styles html email
                local $/;
                my $htmlstylefile = $htmlpagepath . "mailstats.css";
                open my $fh, '<', $htmlstylefile
                  or die "can't open $htmlstylefile: $!";
                my $htmlstyle = <$fh>;

                #and replace </head> by "<style><css contents></style></head>
                $html =~ s%</head>%<style>\n$htmlstyle</style></head>\n%;
                open( SENDMAIL, "|$opt{'sendmail'} -oi -t -odq" )
                  or die "Can't open sendmail: $!\n";
                print SENDMAIL "From: $opt{'from'}\n";
                print SENDMAIL "To: $opt{'mail'}\n";
                print SENDMAIL
                  "Subject: Spam Filter Statistics from $hostname - ",
                  strftime( "%F", localtime($start) ), "\n";
                print SENDMAIL "MIME-Version: 1.0\n";
                if ( $makeHTMLemail eq "both" ) {
                    print SENDMAIL "Content-Type: multipart/alternative;\n";
                    print SENDMAIL
                      ' boundary="------------1916B385DAEB611B3336A1A0"' . "\n";
                    print SENDMAIL
                      "This is a multi-part message in MIME format.";
                    print SENDMAIL "--------------1916B385DAEB611B3336A1A0\n";
                    print SENDMAIL
"Content-Type: text/plain; charset=utf-8; format=flowed;\n";
                    print SENDMAIL "Content-Transfer-Encoding: 7bit\n";
                    print SENDMAIL "\n";
                    print SENDMAIL "Mailstats -2016-10-28\n";
                    print SENDMAIL "\n";
                    print SENDMAIL $tablestr . "\n";
                    print SENDMAIL "\n";
                    print SENDMAIL "--------------1916B385DAEB611B3336A1A0\n";
                }
                print SENDMAIL "Content-Type: text/html; charset=utf-8;\n";
                print SENDMAIL "Content-Transfer-Encoding: 7bit;\n";
                print SENDMAIL "\n";
                print SENDMAIL $html . "\n";
                print SENDMAIL "\n";
                if ( $makeHTMLemail eq "both" ) {
                    print SENDMAIL "--------------1916B385DAEB611B3336A1A0\n";
                }
                close(SENDMAIL);
            }
        }
    }

    #Close Sendmail if it was opened
    if ( $opt{'mail'} ) {
        select $oldFH;
        close(SENDMAIL);
    }

}    ##report disabled

#All done
exit 0;

#############################################################################
# Subroutines ###############################################################
#############################################################################

sub show_recip_usage {

    # time to do a 'by recipient domain' report
    $recip_caption = "Incoming mails by recipient domains usage\n";
    print $recip_caption;
    my $line =
"-----------------------------------------------------------------------------------------------\n";
    print $line;
    my $recip_titles;
    push( @{$recip_titles}, { col => sprintf( "%-28s", "Domains" ) } );
    push( @{$recip_titles}, { col => sprintf( "%-10s", "Type" ) } );
    push( @{$recip_titles}, { col => "Total" } );
    push( @{$recip_titles}, { col => "Deny" } );
    push( @{$recip_titles}, { col => "XferErr" } );
    push( @{$recip_titles}, { col => "Accept" } );
    push( @{$recip_titles}, { col => "\%accept" } );
    foreach my $str (@$recip_titles) {
        print $$str{"col"} . "\t";
    }
    push( @{$recip_table}, { cols => $recip_titles } );
    print "\n" . $line;
    my %total = (
        total  => 0,
        deny   => 0,
        xfer   => 0,
        accept => 0,
    );
    foreach my $domain (
        sort {
            join( "\.", reverse( split /\./, $a ) ) cmp
              join( "\.", reverse( split /\./, $b ) )
        } keys %byrcptdomain
      )
    {
        my $recip_cols;
        next if ( ( $byrcptdomain{$domain}{'total'} || 0 ) == 0 );
        my $tp = $byrcptdomain{$domain}{'type'}   || 'other';
        my $to = $byrcptdomain{$domain}{'total'}  || 0;
        my $de = $byrcptdomain{$domain}{'deny'}   || 0;
        my $xr = $byrcptdomain{$domain}{'xfer'}   || 0;
        my $ac = $byrcptdomain{$domain}{'accept'} || 0;

        push( @{$recip_cols}, { col => sprintf( "%-28s", trim($domain) ) } );
        push( @{$recip_cols}, { col => sprintf( "%-10s", $tp ) } );
        push( @{$recip_cols}, { col => sprintf( "%6d",   $to ) } );
        push( @{$recip_cols}, { col => sprintf( "%6d",   $de ) } );
        push( @{$recip_cols}, { col => sprintf( "%8d",   $xr ) } );
        push( @{$recip_cols}, { col => sprintf( "%6d",   $ac ) } );
        push( @{$recip_cols},
            { col => sprintf( "%6.2f%%", $ac * 100 / $to ) } );

        #printf "%-28s %-10s %6d %6d %7d %6d %6.2f%%\n", $domain, $tp, $to,
        #$de, $xr, $ac, $ac * 100 / $to;
        $total{'total'}  += $to;
        $total{'deny'}   += $de;
        $total{'xfer'}   += $xr;
        $total{'accept'} += $ac;
        push( @{$recip_table}, { cols => $recip_cols } );
        foreach my $str (@$recip_cols) {
            print $$str{"col"} . "\t";
        }
        print "\n";
    }
    print $line;
    my $recip_totals;

    # $total{ 'total' } can be equal to 0, bad for divisions...
    my $perc1 = 0;
    my $perc2 = 0;

    if ( $total{'total'} != 0 ) {
        $perc1 = $total{'accept'} * 100 / $total{'total'};
        $perc2 = ( ( $total{'total'} + $morethanonercpt ) / $total{'total'} );
    }

    push( @{$recip_totals}, { col => sprintf( "%-28s", "Totals" ) } );
    push( @{$recip_totals}, { col => sprintf( "%-10s", "" ) } );
    push( @{$recip_totals}, { col => sprintf( "%6d",   $total{'total'} ) } );
    push( @{$recip_totals}, { col => sprintf( "%6d",   $total{'deny'} ) } );
    push( @{$recip_totals}, { col => sprintf( "%8d",   $total{'xfer'} ) } );
    push( @{$recip_totals}, { col => sprintf( "%6d",   $total{'accept'} ) } );
    push( @{$recip_totals}, { col => sprintf( "%6.2f%%\n", $perc1 ) } );
    foreach my $str (@$recip_totals) {
        print $$str{"col"} . "\t";
    }
    push( @{$recip_table}, { cols => $recip_totals } );

#printf
#"%d mails were processed for %d Recipients\nThe average recipients by mail is %4.2f\n\n",
#$total{'total'}, ( $total{'total'} + $morethanonercpt ), $perc2;
    return;
}

sub show_virus_variants

  #
  # Show a league table of the different virus types found today
  #

{
    my $line =
"------------------------------------------------------------------------\n";
    $virus_caption = "\nVirus Statistics by name:\n";
    print( $virus_caption. $line );
    foreach my $virus (
        sort { $found_viruses{$b} <=> $found_viruses{$a} }
        keys %found_viruses
      )
    {
        my $virus_cols;
        if (   index( $virus, "Sanesecurity" ) != -1
            or index( $virus, "UNOFFICIAL" ) != -1 )
        {
            push(
                @{$virus_cols},
                {
                    col => "Rejected\t",
                    col =>
"$found_viruses{$virus}\thttp://sane.mxuptime.com/s.aspx?id=$virus\n"
                }
            );
        }
        else {
            push(
                @{$virus_cols},
                {
                    col => "Rejected\t",
                    col => "$found_viruses{$virus}\t$virus\n"
                }
            );
        }
        push( @{$virus_table}, { cols => $virus_cols } );
        foreach my $str (@$virus_cols) {
            print $$str{"col"} . " ";
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
    $qpsmtpd_caption = "\nQpsmtpd codes league table:\n";
    print( $qpsmtpd_caption. $line );
    my $qpsmtpd_titles;
    push( @{$qpsmtpd_titles}, { col => "Reason" } );
    push( @{$qpsmtpd_titles}, { col => "Count" } );
    push( @{$qpsmtpd_titles}, { col => "Percent" } );

    foreach my $str (@$qpsmtpd_titles) {
        print $$str{"col"} . "\t";
    }
    push( @{$qpsmtpd_table}, { cols => $qpsmtpd_titles } );
    print( "\n" . $line );

    foreach my $qpcode (
        sort { $found_qpcodes{$b} <=> $found_qpcodes{$a} }
        keys %found_qpcodes
      )
    {
        my $qpsmtpd_cols;
        push( @{$qpsmtpd_cols},  { col  => $qpcode } );
        push( @{$qpsmtpd_cols}, { col => sprintf("%-5d",$found_qpcodes{$qpcode}) } );
        push(
            @{$qpsmtpd_cols},
            {
                col => sprintf( '%4.1f%%',
                    $found_qpcodes{$qpcode} * 100 / $totalexamined )
            }
        );

        push( @{$qpsmtpd_table}, { cols => $qpsmtpd_cols } );
        foreach my $str (@$qpsmtpd_cols) {
            print $$str{"col"} . "\t";
        }
        print "\n";
    }
    print($line);
	my $qpsmtpd_cols;
	push( @{$qpsmtpd_cols}, { col => "Totals" } );
	push( @{$qpsmtpd_cols}, { col => "$totalexamined" } );
	push( @{$qpsmtpd_cols},
		{ col => sprintf( "%4d%%", 100 ) } );
	foreach my $str (@$qpsmtpd_cols) {
		print $$str{"col"}."\t";
	}
	print "\n";
	push( @{$qpsmtpd_table}, { cols => $qpsmtpd_cols } );
	print($line);

}

sub show_blacklist_counts

  #
  # Show a sorted league table of the blacklist URL counts
  #

{
    my $line = "------------------\n";
    $blacklistsettings_caption = "\nBlacklists specified:\n";
    print $blacklistsettings_caption;
    print($line);
    my $blacklistsettings_titles;
    push( @{$blacklistsettings_titles}, { col => "Type" } );
    push( @{$blacklistsettings_titles}, { col => "List" } );
    foreach my $str (@$blacklistsettings_titles) {
        print $$str{"col"} . "\t";
    }
    push( @{$blacklistsettings_table}, { cols => $blacklistsettings_titles } );
    print( "\n" . $line );  
    my %lists =
      ( RHSBL => "RBLList", URIBL => "UBLList", DNSBL => "SBLList" );
    foreach my $list ( keys %lists ) {
        if ( $cdb->get('qpsmtpd')->prop("$list") eq "enabled" ) {
            my @listcontents = split(',',$cdb->get('qpsmtpd')->prop($lists{$list}));

            #Remove empty entries
            # Magic code taken from https://stackoverflow.com/questions/22722004/remove-empty-strings-in-perl-hash-of-arrays
            #@$_ = grep defined && length, @$_ for values %listcontents; 
            #foreach my $keys ( keys %listcontents) {
		    #		$listcontents{$keys} = [grep { length $_ } @{$listcontents{$keys}}];
			#}
            foreach my $content (@listcontents){	
				my $blacklistsettings_cols;
				push( @{$blacklistsettings_cols}, { col => "$list" } );
				push(
					@{$blacklistsettings_cols},
					{ col => $content }
				);
				push(
					@{$blacklistsettings_table},
					{ cols => $blacklistsettings_cols }
				);

				foreach my $str (@$blacklistsettings_cols) {
					print $$str{"col"} . "\t";
				}
				print "\n";
			}
        }
    }
    print($line);
   	my $blacklistsettings_cols;
	push( @{$blacklistsettings_cols}, { col => "" } );
	push( @{$blacklistsettings_cols}, { col => "" } );
	push(
		@{$blacklistsettings_table},
		{ cols => $blacklistsettings_cols }
	);
	foreach my $str (@$blacklistsettings_cols) {
		print $$str{"col"};
	}
	print "\n";

    $blacklistuse_caption = "\nBlacklist use:\n";
    print $blacklistuse_caption;
    print($line);
    my $blacklistuse_titles;
    push( @{$blacklistuse_titles}, { col => "URL" } );
    push( @{$blacklistuse_titles}, { col => "\tCount" } );

    foreach my $str (@$blacklistuse_titles) {
        print $$str{"col"} . "\t";
    }
    push( @{$blacklistuse_table}, { cols => $blacklistuse_titles } );
    print( "\n" . $line );
    my $blacklistURLcount = 0;
    foreach my $blcode (
        sort { $blacklistURL{$b} <=> $blacklistURL{$a} }
        keys %blacklistURL
      )
    {
        my $blacklistuse_cols;

        push( @{$blacklistuse_cols}, { col => "\t$blcode" } );
        push(
            @{$blacklistuse_cols},
            { col => sprintf( '%3u', $blacklistURL{$blcode} ) }
        );
        $blacklistURLcount = $blacklistURLcount + $blacklistURL{$blcode};
        foreach my $str (@$blacklistuse_cols) {
            print $$str{"col"} . "\t";
        }
        push( @{$blacklistuse_table}, { cols => $blacklistuse_cols } );
        print "\n";
    }
    print($line);
	my $blacklistuse_cols;
	push( @{$blacklistuse_cols}, { col => "Totals" } );
	push( @{$blacklistuse_cols}, { col => $blacklistURLcount } );
	foreach my $str (@$blacklistuse_cols) {
		print $$str{"col"};
	}
	print "\n";
	push( @{$blacklistuse_table}, { cols => $blacklistuse_cols } );
	print($line);

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
        my $line = "---------------------------\n";
        $junkmail_caption = "\nJunk Mails left in folder:\n";
        print $junkmail_caption;
        print($line);
        my $junkmail_titles;
        push( @{$junkmail_titles}, { col => "User" } );
        push( @{$junkmail_titles}, { col => "Count" } );
        foreach my $str (@$junkmail_titles) {
            print $$str{"col"} . "\t";
        }
        push( @{$junkmail_table}, { cols => $junkmail_titles } );
        print( "\n" . $line );
        my $junkmailcount = 0;
        foreach my $thisuser (
            sort { $junkcount{$b} <=> $junkcount{$a} }
            keys %junkcount
          )
        {
            my $junkmail_cols;
            $junkmailcount = $junkmailcount + $junkcount{$thisuser};
            push( @{$junkmail_cols}, { col => "\t$thisuser" } );
            push(
                @{$junkmail_cols},
                { col => sprintf( "%d", $junkcount{$thisuser} ) }
            );
            foreach my $str (@$junkmail_cols) {
                print $$str{"col"};
            }
            push( @{$junkmail_table}, { cols => $junkmail_cols } );
            print "\n";
        }
        print($line);
	    my $junkmail_cols;
		push( @{$junkmail_cols}, { col => "Totals" } );
		push( @{$junkmail_cols}, { col => $junkmailcount} );
		foreach my $str (@$junkmail_cols) {
			print $$str{"col"};
		}
		print "\n";
		push( @{$junkmail_table}, { cols => $junkmail_cols } );
		print($line);

    }
    else {
        print "***No junkmail folders with emails***\n";
    }
}

sub show_user_stats

  #
  # Show a sorted league table of the user counts
  #

{

    #Compute totals for each entry
    my $grandtotals   = 0;
    my $totalqueued   = 0;
    my $totalspam     = 0;
    my $totalrejected = 0;
    foreach my $user ( keys %usercounts ) {
        $usercounts{$user}{"queued"} = 0
          if !( exists $usercounts{$user}{"queued"} );
        $usercounts{$user}{"rejected"} = 0
          if !( exists $usercounts{$user}{"rejected"} );
        $usercounts{$user}{"spam"} = 0
          if !( exists $usercounts{$user}{"spam"} );
        $usercounts{$user}{"totals"} =
          $usercounts{$user}{"queued"} +
          $usercounts{$user}{"rejected"} +
          $usercounts{$user}{"spam"};
        $grandtotals   += $usercounts{$user}{"totals"};
        $totalspam     += $usercounts{$user}{"spam"};
        $totalqueued   += $usercounts{$user}{"queued"};
        $totalrejected += $usercounts{$user}{"rejected"};
    }
    my $line = "--------------------------------------------------\n";
    $emails_caption = "\nStatistics by email address received:\n";
    print $emails_caption;
    print($line);
    my $emails_titles;
    push( @{$emails_titles}, { col => "\tEmail Address" } );
    push( @{$emails_titles}, { col => "Queued" } );
    push( @{$emails_titles}, { col => "\tRejected" } );
    push( @{$emails_titles}, { col => "\tSpam tagged" } );


    foreach my $str (@$emails_titles) {
        print $$str{"col"};
    }
    push( @{$emails_table}, { cols => $emails_titles } );
    print( "\n" . $line );
    foreach my $user (
        sort { $usercounts{$b}{"totals"} <=> $usercounts{$a}{"totals"} }
        keys %usercounts
      )
    {
        my $emails_cols;
        my $usernomailto = $user;
        $usernomailto =~ s/(\<|\>)//g;
        push( @{$emails_cols}, { col => $usernomailto } );
        push(
            @{$emails_cols},
            { col => sprintf( '%3u', $usercounts{$user}{"queued"} ) . "\t" }
        );
        push(
            @{$emails_cols},
            {
                col => sprintf( '%3u', $usercounts{$user}{"rejected"} ) . "\t\t"
            }
        );
        push(
            @{$emails_cols},
            { col => sprintf( '%3u', $usercounts{$user}{"spam"} ) . "\t\t" }
        );
        foreach my $str (@$emails_cols) {
            print $$str{"col"};
        }
        print "\n";
        push( @{$emails_table}, { cols => $emails_cols } );
    }
    print($line);
    my $emails_footcols;
    push( @{$emails_footcols}, { col => "Totals" } );
    push(
        @{$emails_footcols},
        { col => sprintf( '%3u', $totalqueued ) . "\t" }
    );
    push(
        @{$emails_footcols},
        { col => sprintf( '%3u', $totalrejected ) . "\t\t" }
    );
    push( @{$emails_footcols}, { col => sprintf( '%3u', $totalspam ) } );

    foreach my $str (@$emails_footcols) {
        print $$str{"col"};
    }
    push( @{$emails_table}, { cols => $emails_footcols } );
    print "\n";
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
    my ($totalpercent) = 0;
    if ( $cdb->get('mailstats') ) {
        $percentthreshold = $cdb->get('mailstats')->prop("GeoipCutoffPercent")
          || 0.5;
    }
    else {
        $percentthreshold = 0.5;
    }
 
	my $line = "---------------------------------------------\n";
	$geoip_caption = "\nGeoip results: (cutoff at $percentthreshold%) \n";
	print $geoip_caption;
	print($line);
	my $geoip_titles;
	push( @{$geoip_titles}, { col => "Country" } );
	push( @{$geoip_titles}, { col => "\tCount" } );
	push( @{$geoip_titles}, { col => "\tPercent" } );

	foreach my $str (@$geoip_titles) {
		print $$str{"col"};
	}
	push( @{$geoip_table}, { cols => $geoip_titles } );
	print( "\n" . $line );
   
    if ( $total_countries > 0 ) {
         foreach my $country (
            sort { $found_countries{$b} <=> $found_countries{$a} }
            keys %found_countries
          )
        {
			if ( $total_countries > 0 ) {
                $percent = $found_countries{$country} * 100 / $total_countries;
                $totalpercent = $totalpercent + $percent;
                if ( index( $BadCountries, $country ) != -1 ) { $reject = "*"; }
                else                                          { $reject = " "; }
                if ( $percent >= $percentthreshold ) {
                    my $geoip_cols;
                    push( @{$geoip_cols}, { col => "$country\t\t" } );
                    push(
                        @{$geoip_cols},
                        { col => "\t$found_countries{$country}" }
                    );
					my $percentcol = sprintf( '%4.1f%%', $percent );
					$percentcol .= $reject;
                    push(
                        @{$geoip_cols},
                        { col => $percentcol . "\t" }
                    );
                    foreach my $str (@$geoip_cols) {
                        print $$str{"col"};
                    }
                    print "\n";
                    push( @{$geoip_table}, { cols => $geoip_cols } );
                }
            }

        }
        print($line);
        my $showtotals;
        if ( $cdb->get('mailstats') ) {
            $showtotals = (
                (
                    (
                        $cdb->get('mailstats')->prop("ShowLeagueTotals")
                          || 'yes'
                    )
                ) eq "yes"
            );
        }
        else {
            $showtotals = $true;
        }

        if ($showtotals) {
            my $geoip_cols;
            push( @{$geoip_cols}, { col => "Totals\t\t" } );
            push( @{$geoip_cols}, { col => "\t\t$total_countries" } );
            push( @{$geoip_cols},
                { col => sprintf( "%5d%%", $totalpercent ) } );
            foreach my $str (@$geoip_cols) {
                print $$str{"col"};
            }
            print "\n";
            push( @{$geoip_table}, { cols => $geoip_cols } );
            print($line);
        }
    }
}

sub show_SARules_codes

#
# Show a league table of the SARules result codes found today
# suppress any lower than DB mailstats/SARulePercentThreshold
# TBD - move to html processing - not done currenlty as SPammasassin rules not shown in latest qpsmtpd logs..bjr - 27thOct16

{
    my ($percentthreshold);
    my ($defaultpercentthreshold);
    my ($totalpercent) = 0;

    if ( $sum_SARules > 0 ) {

        if (    $totalexamined > 0
            and $sum_SARules * 100 / $totalexamined > $SARulethresholdPercent )
        {
            $defaultpercentthreshold = $maxcutoff;
        }
        else {
            $defaultpercentthreshold = $mincutoff;
        }
        if ( $cdb->get('mailstats') ) {
            $percentthreshold =
                 $cdb->get('mailstats')->prop("SARulePercentThreshold")
              || $defaultpercentthreshold;
        }
        else {
            $percentthreshold = $defaultpercentthreshold;
        }
        my $line = "---------------------------------------------\n";
        print(  "\nSpamassassin Rules:(cutoff at "
              . sprintf( '%4.1f', $percentthreshold )
              . "%)\n" );
        print($line);
        print("Count\tPercent\tScore\t\t\n");
        print($line);
        foreach my $SARule (
            sort { $found_SARules{$b}{'count'} <=> $found_SARules{$a}{'count'} }
            keys %found_SARules
          )
        {
            my $percent =
              $found_SARules{$SARule}{'count'} * 100 / $totalexamined
              if $totalexamined;
            my $avehits =
              $found_SARules{$SARule}{'totalhits'} /
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
        if ( $cdb->get('mailstats') ) {
            $showtotals = (
                (
                    (
                        $cdb->get('mailstats')->prop("ShowLeagueTotals")
                          || 'yes'
                    )
                ) eq "yes"
            );
        }
        else {
            $showtotals = $true;
        }

        if ($showtotals) {
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
    if ( ( $currentrcptdomain{$proc} || '' ) ne '' ) {
        $byrcptdomain{ $currentrcptdomain{$proc} }{'deny'}++;
        $currentrcptdomain{$proc} = '';
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
    my $host   = esmith::ConfigDB->open_ro->get('mailstats')->prop('DBHost')
      || "localhost";
    my $port = esmith::ConfigDB->open_ro->get('mailstats')->prop('DBPort')
      || "3306";

    #print "Saving data..";
    my $dbh = DBI->connect( "DBI:mysql:database=$DBname;host=$host;port=$port",
        "mailstats", "mailstats" )
      or die "Cannot open mailstats db - has it beeen created?";

    my $hour = floor( $start / 3600 );
    my $reportdate = strftime( "%F", localtime( $hour * 3600 ) );
    my $reccount = 0;    #count number of records written
    $dateid = get_dateid( $dbh, $reportdate );

#Start by pruning the MySQL data tables so that only the specified number of days of
# data is left in the files
# Get List of the dates previous to the expiry period
    my $sql =
        "SELECT * FROM date WHERE date < '"
      . $firstDay
      . "'AND servername='"
      . $servername . "'";
    my $sth = $dbh->prepare($sql)
      or die("Error Getting expired dates from date table");
    $sth->execute();
    while ( my $row = $sth->fetchrow_hashref() ) {

        # delete from logdata and Loglines counts tables
        my $thisdateid = $row->{"dateid"};
        $dbh->do( "DELETE from LogData WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from logdata");
        $dbh->do( "DELETE from LoglinesInCount WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from logdata counts");
        $dbh->do( "DELETE from JunkMailStats WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from JunkMailStats table");
        $dbh->do( "DELETE from SARules WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from SARules table");
        $dbh->do( "DELETE from qpsmtpdcodes WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from qpsmtpdcodes table");
        $dbh->do( "DELETE from VirusStats WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from VirusStats table");
        $dbh->do( "DELETE from domains WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from domains table");
        $dbh->do( "DELETE from ColumnStats WHERE dateid = "
              . $thisdateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on deleting from ColumnStats table");
    }

    #and prune the date table
    $dbh->do( "DELETE from date WHERE date < '"
          . $firstDay
          . "'AND servername='"
          . $servername
          . "'" );

    # now fill in day related stats  - must always check for it already there
    # incase the module is run more than once in a day
    my $SAScoresid = check_date_rec( $dbh, "SAscores", $dateid, $servername );
    $dbh->do( "UPDATE SAscores SET "
          . "acceptedcount="
          . $spamcount
          . ",rejectedcount="
          . $above15
          . ",hamcount="
          . $hamcount
          . ",acceptedscore="
          . $spamhits
          . ",rejectedscore="
          . $rejectspamhits
          . ",hamscore="
          . $hamhits
          . ",totalsmtp="
          . $totalexamined
          . ",totalrecip="
          . $recipcount
          . ",servername='"
          . $servername
          . "' WHERE SAscoresid ="
          . $SAScoresid );

    # Junkmail stats
    # delete if already there
    $dbh->do( "DELETE from JunkMailStats WHERE dateid = " 
          . $dateid
          . " AND servername='"
          . $servername
          . "'" );

    # and add records
    foreach my $thisuser ( keys %junkcount ) {
        $dbh->do(
            "INSERT INTO JunkMailStats (dateid,user,count,servername) VALUES ('"
              . $dateid . "','"
              . $thisuser . "','"
              . $junkcount{$thisuser} . "','"
              . $servername
              . "')" );
        $reccount++;
    }

    #SA rules - delete any first
    $dbh->do( "DELETE from SARules WHERE dateid = " 
          . $dateid
          . " AND servername='"
          . $servername
          . "'" );

    # and add records
    foreach my $thisrule ( keys %found_SARules ) {
        $dbh->do(
"INSERT INTO SARules (dateid,rule,count,totalhits,servername) VALUES ('"
              . $dateid . "','"
              . $thisrule . "','"
              . $found_SARules{$thisrule}{'count'} . "','"
              . $found_SARules{$thisrule}{'totalhits'} . "','"
              . $servername
              . "')" );
        $reccount++;
    }

    #qpsmtpd result codes
    $dbh->do( "DELETE from qpsmtpdcodes WHERE dateid = " 
          . $dateid
          . " AND servername='"
          . $servername
          . "'" );

    # and add records
    foreach my $thiscode ( keys %found_qpcodes ) {
        $dbh->do(
"INSERT INTO qpsmtpdcodes (dateid,reason,count,servername) VALUES ('"
              . $dateid . "','"
              . $thiscode . "','"
              . $found_qpcodes{$thiscode} . "','"
              . $servername
              . "')" );
        $reccount++;
    }

    # virus stats
    $dbh->do( "DELETE from VirusStats WHERE dateid = " 
          . $dateid
          . " AND servername='"
          . $servername
          . "'" );

    # and add records
    foreach my $thisvirus ( keys %found_viruses ) {
        $dbh->do(
            "INSERT INTO VirusStats (dateid,descr,count,servername) VALUES ('"
              . $dateid . "','"
              . $thisvirus . "','"
              . $found_viruses{$thisvirus} . "','"
              . $servername
              . "')" );
        $reccount++;

    }

    # domain details
    $dbh->do( "DELETE from domains WHERE dateid = " 
          . $dateid
          . " AND servername='"
          . $servername
          . "'" );

    # and add records
    foreach my $domain ( keys %byrcptdomain ) {
        next if ( ( $byrcptdomain{$domain}{'total'} || 0 ) == 0 );
        $dbh->do(
"INSERT INTO domains (dateid,domain,type,total,denied,xfererr,accept,servername) VALUES ('"
              . $dateid . "','"
              . $domain . "','"
              . ( $byrcptdomain{$domain}{'type'} || 'other' ) . "','"
              . $byrcptdomain{$domain}{'total'} . "','"
              . ( $byrcptdomain{$domain}{'deny'}   || 0 ) . "','"
              . ( $byrcptdomain{$domain}{'xfer'}   || 0 ) . "','"
              . ( $byrcptdomain{$domain}{'accept'} || 0 ) . "','"
              . $servername
              . "')" );
        $reccount++;

    }

# the hourly breakdown  - need to remember here that the date might change during the 24 hour span
    my $nhour = floor( $start / 3600 );
    my $ncateg;
    while ( $nhour < $end / 3600 ) {

        #see if the time record has been created
        #       print strftime("%H",localtime( $nhour * 3600 ) ).":00:00\n";
        my $sth =
          $dbh->prepare( "SELECT timeid FROM time WHERE time = '"
              . strftime( "%H", localtime( $nhour * 3600 ) )
              . ":00:00'" );
        $sth->execute();
        if ( $sth->rows == 0 ) {

            #create entry
            $dbh->do( "INSERT INTO time (time) VALUES ('"
                  . strftime( "%H", localtime( $nhour * 3600 ) )
                  . ":00:00')" );

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
        if ( $currentdate ne $reportdate ) {

            #same as before?
            $dateid = get_dateid( $dbh, $currentdate );
            $reportdate = $currentdate;
        }

        # delete for this date and time
        $dbh->do( "DELETE from ColumnStats WHERE dateid = " 
              . $dateid
              . " AND timeid = "
              . $timeid
              . " AND servername='"
              . $servername
              . "'" );
        while ( $ncateg < @categs - 1 ) {

            # then add in each entry
            if ( ( $counts{$nhour}{ $categs[$ncateg] } || 0 ) != 0 ) {
                $dbh->do(
"INSERT INTO ColumnStats (dateid,timeid,descr,count,servername) VALUES ("
                      . $dateid . ","
                      . $timeid . ",'"
                      . $categs[$ncateg] . "',"
                      . $counts{$nhour}{ $categs[$ncateg] } . ",'"
                      . $servername
                      . "')" );
                $reccount++;
            }
            $ncateg++;
        }
        $nhour++;
    }

    # and write out the log lines saved - only if html wanted
    if (   $makeHTMLemail eq 'yes'
        or $makeHTMLemail eq 'both'
        or $makeHTMLpage  eq 'yes' )
    {

# LogData
# and delete any potential duplicate records from a previous run on the same date
        $dbh->do( "DELETE from LogData WHERE dateid = " 
              . $dateid
              . " AND servername='"
              . $servername
              . "'" )
          or die("Error on samedate delete for LogData");
        foreach my $logid ( keys %LogLines ) {

            #Extract from keys
            my $extract = $logid;
            $extract =~ /^(.*)-(.*):(.*)$/;
            my $Log64n    = $1;
            my $LogMailId = $2;
            my $LogSeq    = $3;
            my $LogLine   = $dbh->quote( $LogLines{$logid} );
            my $sql =
"INSERT INTO LogData (Log64n,MailID,Sequence,LogStr,dateid,servername) VALUES ('";
            $sql .=
                $Log64n . "','"
              . $LogMailId . "','"
              . $LogSeq . "',"
              . $LogLine . ","
              . $dateid . ",'"
              . $servername . "')";
            $dbh->do($sql) or die("Write to LogData $sql");
            $reccount++;
        }

        # and the Save the link between the counts and the loglines
        $dbh->do( "DELETE from LoglinesInCount WHERE dateid = " 
              . $dateid
              . " AND servername='"
              . $servername
              . "'" );
        foreach my $i ( 0 .. $#emails_per_count_id ) {
            my $Mailid  = $emails_per_count_id[$i]{mailid};
            my $countid = $emails_per_count_id[$i]{countid};
            my $sql =
"INSERT INTO LoglinesInCount (MailId,Count_id,dateid,servername) VALUES ('";
            $sql .=
                $Mailid . "','" 
              . $countid . "'," 
              . $dateid . ",'"
              . $servername . "')";
            $dbh->do($sql) or die("Write to LogLinesinCount $sql");
            $reccount++;
        }
    }

    $dbh->disconnect();
    $telapsed = time - $tstart;
}

sub check_date_rec

  #
  # check that a specific dated rec is there, create if not
  #
{
    my ( $dbh, $table, $dateid ) = @_;
    my $sth =
      $dbh->prepare( "SELECT " 
          . $table
          . "id FROM "
          . $table
          . " WHERE dateid = '$dateid'" );
    $sth->execute();
    if ( $sth->rows == 0 ) {

        #create entry
        $dbh->do(
            "INSERT INTO " . $table . " (dateid) VALUES ('" . $dateid . "')" );

        # and pick up recordid
        $sth = $dbh->prepare(
            "SELECT last_insert_id() AS " . $table . "id FROM " . $table );
        $sth->execute();
    }
    my $rec = $sth->fetchrow_hashref();
    $rec->{ $table . "id" };    #return the id of the record (new or not)
}

sub check_time_rec

  #
  # check that a specific dated amd timed rec is there, create if not
  #
{
    my ( $dbh, $table, $dateid, $timeid ) = @_;
    my $sth =
      $dbh->prepare( "SELECT " 
          . $table
          . "id FROM "
          . $table
          . " WHERE dateid = '$dateid' AND timeid = "
          . $timeid );
    $sth->execute();
    if ( $sth->rows == 0 ) {

        #create entry
        $dbh->do( "INSERT INTO " 
              . $table
              . " (dateid,timeid) VALUES ('"
              . $dateid . "', '"
              . $timeid
              . "')" );

        # and pick up recordid
        $sth = $dbh->prepare(
            "SELECT last_insert_id() AS " . $table . "id FROM " . $table );
        $sth->execute();
    }
    my $rec = $sth->fetchrow_hashref();
    $rec->{ $table . "id" };    #return the id of the record (new or not)
}

sub get_dateid

  #
  # Check that date is in db, and return corresponding id
  #
{
    my ( $dbh, $reportdate ) = @_;
    my $sth =
      $dbh->prepare( "SELECT dateid FROM date WHERE date = '"
          . $reportdate
          . "'AND servername='"
          . $servername
          . "'" );
    $sth->execute();
    if ( $sth->rows == 0 ) {

        #create entry
        $dbh->do( "INSERT INTO date (date,servername) VALUES ('"
              . $reportdate . "','"
              . $servername
              . "')" );

        # and pick up dateid
        $sth = $dbh->prepare("SELECT last_insert_id() AS dateid FROM date");
        $sth->execute();
    }
    my $daterec = $sth->fetchrow_hashref();
    $daterec->{"dateid"};
}

################################################
# Determine analysis period (start and end time)
################################################
sub analysis_period {
    my $startdate = shift;
    my $enddate   = shift;

    my $secsininterval = 86400;    #daily default
    my $time;

    if ( $cdb->get('mailstats') ) {
        my $interval = $cdb->get('mailstats')->prop('Interval') || 'daily';
        if ( $interval eq "weekly" ) {
            $secsininterval = 86400 * 7;
        }
        elsif ( $interval eq "fortnightly" ) {
            $secsininterval = 86400 * 14;
        }
        elsif ( $interval eq "monthly" ) {
            $secsininterval = 86400 * 30;
        }
        elsif ( $interval =~ m/\d+/ ) {
            $secsininterval = $interval * 3600;
        }
        my $base = $cdb->get('mailstats')->prop('Base') || 'Midnight';
        my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
          localtime(time);
        if ( $base eq "Midnight" ) {
            $sec  = 0;
            $min  = 0;
            $hour = 0;
        }
        elsif ( $base eq "Midday" ) {
            $sec  = 0;
            $min  = 0;
            $hour = 12;
        }
        elsif ( $base =~ m/\d+/ ) {
            $sec  = 0;
            $min  = 0;
            $hour = $base;
        }
        $time = timelocal( $sec, $min, $hour, $mday, $mon, $year );
    }

    my $start = str2time($startdate);
    my $end =
        $enddate   ? str2time($enddate)
      : $startdate ? $start + $secsininterval
      :              $time;
    $start = $startdate ? $start : $end - $secsininterval;
    return ( $start > $end ) ? ( $end, $start ) : ( $start, $end );
}

sub test_for_private_ip {
    use NetAddr::IP;
    $_ = shift;
    return unless /(\d+\.\d+\.\d+\.\d+)/;
    my $ip = NetAddr::IP->new($1);
    return unless $ip;
    return $ip->is_rfc1918();
}

sub trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s }

sub get_domain {
    my $url = shift;
    $url =~ s!^\(dnsbl\)\s!!;
    $url =~ s!^.*https?://(?:www\.)?!!i;
    $url =~ s!/.*!!;
    $url =~ s/[\?\#\:].*//;
    $url =~ s/^([\d]{1,3}.){4}//;
    my $domain = trim($url);
    return $domain;
}

sub push_count_ids {
    my $CurrentMailId = shift;
    my $abshour       = shift;
    my $CATEGORY      = shift;
    push( @emails_per_count_id,
        { mailid => $CurrentMailId, countid => $count_id{$abshour}{$CATEGORY} }
    );
    push(
        @emails_per_count_id,
        {
            mailid  => $CurrentMailId,
            countid => $count_id{$GRANDTOTAL}{$CATEGORY}
        }
    );
    push(
        @emails_per_count_id,
        {
            mailid  => $CurrentMailId,
            countid => $count_id{$abshour}{ $categs[ @categs - 2 ] }
        }
    );
    push(
        @emails_per_count_id,
        {
            mailid  => $CurrentMailId,
            countid => $count_id{$GRANDTOTAL}{ $categs[ @categs - 2 ] }
        }
    );
}

sub wh_log {
    my $msg         = shift;
    my $debug       = 0;
    my $nodebugfile = 1;
    my $logfile     = "mailstats.log";
    my $fullmsg     = strftime("Y-m-d H:i:s") . "| " . $msg . "\n";
    if ($debug) { print $fullmsg; }
    if ( !$nodebugfile ) {
        open( FILE, ">> $logfile" ) || die "problem opening $logfile\n";
        print FILE $msg;
        close(FILE);
    }

    #$sendmsg .= date("Y-m-d H:i:s")." | ".$msg."\n";
}

sub space2hex {
    my $text = shift;
    $text =~ s/ /%20/g;
    return $text;
}

