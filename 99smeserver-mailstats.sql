CREATE DATABASE IF NOT EXISTS `mailstats`;

USE `mailstats`;

CREATE TABLE IF NOT EXISTS `ColumnStats` (
  `ColumnStatsid` int(11) NOT NULL auto_increment,
  `dateid` int(11) NOT NULL default '0',
  `timeid` int(11) NOT NULL default '0',
  `descr` varchar(20) NOT NULL default '',
  `count` bigint(20) NOT NULL default '0',
  `servername` varchar(30) NOT NULL default '',
  PRIMARY KEY  (`ColumnStatsid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `JunkMailStats` (
  `JunkMailstatsid` int(11) NOT NULL auto_increment,
  `dateid` int(11) NOT NULL default '0',
 `user` varchar(12) NOT NULL default '',
  `count` bigint(20) NOT NULL default '0',
  `servername` varchar(30) default NULL,
  PRIMARY KEY  (`JunkMailstatsid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `SARules` (
  `SARulesid` int(11) NOT NULL auto_increment,
  `dateid` int(11) NOT NULL default '0',
  `rule` varchar(50) NOT NULL default '',
  `count` bigint(20) NOT NULL default '0',
  `totalhits` bigint(20) NOT NULL default '0',
  `servername` varchar(30) NOT NULL default '',
  PRIMARY KEY  (`SARulesid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `SAscores` (
  `SAscoresid` int(11) NOT NULL auto_increment,
  `dateid` int(11) NOT NULL default '0',
  `acceptedcount` bigint(20) NOT NULL default '0',
  `rejectedcount` bigint(20) NOT NULL default '0',
  `hamcount` bigint(20) NOT NULL default '0',
  `acceptedscore` decimal(20,2) NOT NULL default '0.00',
  `rejectedscore` decimal(20,2) NOT NULL default '0.00',
  `hamscore` decimal(20,2) NOT NULL default '0.00',
  `totalsmtp` bigint(20) NOT NULL default '0',
  `totalrecip` bigint(20) NOT NULL default '0',
  `servername` varchar(30) NOT NULL default '',
  PRIMARY KEY  (`SAscoresid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `VirusStats` (
  `VirusStatsid` int(11) NOT NULL auto_increment,
  `dateid` int(11) NOT NULL default '0',
  `descr` varchar(40) NOT NULL default '',
  `count` bigint(20) NOT NULL default '0',
  `servername` varchar(30) NOT NULL default '',
  PRIMARY KEY  (`VirusStatsid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `date` (
  `dateid` int(11) NOT NULL auto_increment,
  `date` date NOT NULL default '0000-00-00',
  PRIMARY KEY  (`dateid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


CREATE TABLE IF NOT EXISTS `domains` (
  `domainsid` int(11) NOT NULL auto_increment,
  `dateid` int(11) NOT NULL default '0',
  `domain` varchar(40) NOT NULL default '',
  `type` varchar(10) NOT NULL default '',
  `total` bigint(20) NOT NULL default '0',
  `denied` bigint(20) NOT NULL default '0',
  `xfererr` bigint(20) NOT NULL default '0',
  `accept` bigint(20) NOT NULL default '0',
  `servername` varchar(30) NOT NULL default '',
  PRIMARY KEY  (`domainsid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `qpsmtpdcodes` (
  `qpsmtpdcodesid` int(11) NOT NULL auto_increment,
  `dateid` int(11) NOT NULL default '0',
  `reason` varchar(40) NOT NULL default '',
  `count` bigint(20) NOT NULL default '0',
  `servername` varchar(30) NOT NULL default '',
  PRIMARY KEY  (`qpsmtpdcodesid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `time` (
  `timeid` int(11) NOT NULL auto_increment,
  `time` time NOT NULL default '00:00:00',
  PRIMARY KEY  (`timeid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `LogData` (
  `LogData_id` int(12) NOT NULL AUTO_INCREMENT,
  `Log64n` varchar(20) NOT NULL,
  `MailId` int(11) NOT NULL,
  `Sequence` smallint(6) NOT NULL,
  `LogStr` text NOT NULL,
  `dateid` int(11) NOT NULL,
  `servername` varchar(30) NOT NULL,
  PRIMARY KEY (`LogData_id`),
  KEY `MailId` (`MailId`),
  KEY `dateid` (`dateid`),
  KEY `servername` (`servername`),
  KEY `Sequence` (`Sequence`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=12988787 ;


CREATE TABLE IF NOT EXISTS `LoglinesInCount` (
  `LoglinesInCount_id` int(11) NOT NULL AUTO_INCREMENT,
  `MailId` int(11) NOT NULL,
  `Count_id` int(11) NOT NULL,
  `dateid` int(11) NOT NULL,
  `servername` varchar(30) NOT NULL,
  PRIMARY KEY (`LoglinesInCount_id`),
  KEY `Count_id` (`Count_id`),
  KEY `MailId` (`MailId`),
  KEY `servername` (`servername`),
  KEY `dateid` (`dateid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=712624 ;


grant all privileges on mailstats.* to 'mailstats'@'localhost' identified by 'mailstats';


