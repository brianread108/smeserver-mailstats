-- phpMyAdmin SQL Dump
-- version 4.0.10.20
-- https://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 26, 2017 at 10:44 AM
-- Server version: 5.1.73
-- PHP Version: 5.3.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `mailstats`
--

-- --------------------------------------------------------

--
-- Table structure for table `ColumnStats`
--

CREATE TABLE IF NOT EXISTS `ColumnStats` (
  `ColumnStatsid` int(11) NOT NULL AUTO_INCREMENT,
  `dateid` int(11) NOT NULL DEFAULT '0',
  `timeid` int(11) NOT NULL DEFAULT '0',
  `descr` varchar(20) NOT NULL DEFAULT '',
  `count` bigint(20) NOT NULL DEFAULT '0',
  `servername` varchar(30) NOT NULL DEFAULT '',
  PRIMARY KEY (`ColumnStatsid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=227505 ;

-- --------------------------------------------------------

--
-- Table structure for table `date`
--

CREATE TABLE IF NOT EXISTS `date` (
  `dateid` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL DEFAULT '0000-00-00',
  `servername` varchar(30) NOT NULL,
  PRIMARY KEY (`dateid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=889 ;

-- --------------------------------------------------------

--
-- Table structure for table `domains`
--

CREATE TABLE IF NOT EXISTS `domains` (
  `domainsid` int(11) NOT NULL AUTO_INCREMENT,
  `dateid` int(11) NOT NULL DEFAULT '0',
  `domain` varchar(40) NOT NULL DEFAULT '',
  `type` varchar(10) NOT NULL DEFAULT '',
  `total` bigint(20) NOT NULL DEFAULT '0',
  `denied` bigint(20) NOT NULL DEFAULT '0',
  `xfererr` bigint(20) NOT NULL DEFAULT '0',
  `accept` bigint(20) NOT NULL DEFAULT '0',
  `servername` varchar(30) NOT NULL DEFAULT '',
  PRIMARY KEY (`domainsid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=7935 ;

-- --------------------------------------------------------

--
-- Table structure for table `JunkMailStats`
--

CREATE TABLE IF NOT EXISTS `JunkMailStats` (
  `JunkMailstatsid` int(11) NOT NULL AUTO_INCREMENT,
  `dateid` int(11) NOT NULL DEFAULT '0',
  `user` varchar(12) NOT NULL DEFAULT '',
  `count` bigint(20) NOT NULL DEFAULT '0',
  `servername` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`JunkMailstatsid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=6000 ;

-- --------------------------------------------------------

--
-- Table structure for table `LogData`
--

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
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=14420906 ;

-- --------------------------------------------------------

--
-- Table structure for table `LogDataSave`
--

CREATE TABLE IF NOT EXISTS `LogDataSave` (
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
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=13321601 ;

-- --------------------------------------------------------

--
-- Table structure for table `LoglinesInCount`
--

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
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=809804 ;

-- --------------------------------------------------------

--
-- Table structure for table `LoglinesInCountSave`
--

CREATE TABLE IF NOT EXISTS `LoglinesInCountSave` (
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
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=716640 ;

-- --------------------------------------------------------

--
-- Table structure for table `qpsmtpdcodes`
--

CREATE TABLE IF NOT EXISTS `qpsmtpdcodes` (
  `qpsmtpdcodesid` int(11) NOT NULL AUTO_INCREMENT,
  `dateid` int(11) NOT NULL DEFAULT '0',
  `reason` varchar(40) NOT NULL DEFAULT '',
  `count` bigint(20) NOT NULL DEFAULT '0',
  `servername` varchar(30) NOT NULL DEFAULT '',
  PRIMARY KEY (`qpsmtpdcodesid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=15576 ;

-- --------------------------------------------------------

--
-- Table structure for table `SARules`
--

CREATE TABLE IF NOT EXISTS `SARules` (
  `SARulesid` int(11) NOT NULL AUTO_INCREMENT,
  `dateid` int(11) NOT NULL DEFAULT '0',
  `rule` varchar(50) NOT NULL DEFAULT '',
  `count` bigint(20) NOT NULL DEFAULT '0',
  `totalhits` bigint(20) NOT NULL DEFAULT '0',
  `servername` varchar(30) NOT NULL DEFAULT '',
  PRIMARY KEY (`SARulesid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=35476 ;

-- --------------------------------------------------------

--
-- Table structure for table `SAscores`
--

CREATE TABLE IF NOT EXISTS `SAscores` (
  `SAscoresid` int(11) NOT NULL AUTO_INCREMENT,
  `dateid` int(11) NOT NULL DEFAULT '0',
  `acceptedcount` bigint(20) NOT NULL DEFAULT '0',
  `rejectedcount` bigint(20) NOT NULL DEFAULT '0',
  `hamcount` bigint(20) NOT NULL DEFAULT '0',
  `acceptedscore` decimal(20,2) NOT NULL DEFAULT '0.00',
  `rejectedscore` decimal(20,2) NOT NULL DEFAULT '0.00',
  `hamscore` decimal(20,2) NOT NULL DEFAULT '0.00',
  `totalsmtp` bigint(20) NOT NULL DEFAULT '0',
  `totalrecip` bigint(20) NOT NULL DEFAULT '0',
  `servername` varchar(30) NOT NULL DEFAULT '',
  PRIMARY KEY (`SAscoresid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=889 ;

-- --------------------------------------------------------

--
-- Table structure for table `time`
--

CREATE TABLE IF NOT EXISTS `time` (
  `timeid` int(11) NOT NULL AUTO_INCREMENT,
  `time` time NOT NULL DEFAULT '00:00:00',
  PRIMARY KEY (`timeid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=25 ;

-- --------------------------------------------------------

--
-- Table structure for table `VirusStats`
--

CREATE TABLE IF NOT EXISTS `VirusStats` (
  `VirusStatsid` int(11) NOT NULL AUTO_INCREMENT,
  `dateid` int(11) NOT NULL DEFAULT '0',
  `descr` varchar(40) NOT NULL DEFAULT '',
  `count` bigint(20) NOT NULL DEFAULT '0',
  `servername` varchar(30) NOT NULL DEFAULT '',
  PRIMARY KEY (`VirusStatsid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=606 ;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
