# smeserver-mailstats
Code for the mailstats contrib on SMEServer (aka Koozali server)

.tmpl files are the html template files used as a template to generate the html.

spamfilter-stats-7.pl (silly name!) is the text only version, currently in use in SME9.2.

mailstats.pl is the WIP html enhanced version (with a better name) it is based on spamfilter-stats-7.pl.

mailstats-detail.php is the server side php which is used to display log file contents on a webpage (hosted locally on the SMEServer)

mailstats.cron is the cron file used to run the mailstats perl program every night. Placed in /etc/cron.d

Details about the use of the package here:
https://wiki.contribs.org/Mailstats
