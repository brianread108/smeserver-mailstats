	<?php
	#
	# Receive call from Mailstats webpage, and display details
	# bjr - initial code - Nov 2016
	# bjr - 08Nov2016  - Convert to PDO:MySQL 
	#
	# $tai64_number = '@400000003c675d4000fbebc';
	#                   12345678901234567890123
	#
	# bjr - 11Dec17 - fix SQL 
	#
	error_reporting(E_ALL & ~E_DEPRECATED);
	ini_set("log_errors", 1);
	ini_set("error_log", "php-error.log");
	
	$maxcssclasses = 13;
	
	function tai64_to_timestamp($tai64_number){
		/*** take out leading @ and the top bit ***/
		$tai64_number = str_replace('@4', '0', $tai64_number);
		/*** strip last 8 chars ***/
		$tai64_number = substr($tai64_number, 0, -7);
		/*** convert to unix timestamp and hexdec ***/
		$tai64_number = intval(hexdec($tai64_number));
		return $tai64_number;
	}
	
	function apply_meta($metas,$line){
		$thisline = $line;
		foreach ($metas as $key=>$val) {
			  $thisline = str_ireplace("@".$key."@",$val,$thisline,$count);
		}
		# and run again to catch meta in meta - not needed in mailstats - detail
		/*
		foreach ($metas as $key=>$val) {
			  $thisline = str_ireplace("@".$key."@",$val,$thisline,$count);
		}
		*/
		
		return $thisline;
	}
	
	function wh_log($msg){
		global $sendmsg,$debug,$nodebugfile,$logfile;
		$mem = ""; #memory_get_usage();
		$fullmsg = date("Y-m-d H:i:s")."($mem) | ".$msg."\n";
		if ($debug) echo $fullmsg;
		if (!$nodebugfile) file_put_contents($logfile,$fullmsg,FILE_APPEND);
		$sendmsg .= date("Y-m-d H:i:s")." | ".$msg."\n";
}

	function wh_log_close($msg){
		global $sendmsg,$event;
		wh_log($msg);
		#mail(EMAILTO,"Mailstats -detail "."-".date("Y-m-d H:i:s"),$sendmsg,"From:".EMAILFROM);
	}
	
	define("EMAILTO","brianr@bjsystems.co.uk");
	define("EMAILFROM","mailstats-detail@bjsystems.co.uk");

	$sendmsg = "";
	$nodebugfile = false;
	$logfile = "mailstats-detail.log";
	$debug = false;

	
	define('DB_NAME','mailstats');
	define('DB_HOST','localhost');
	define('DB_USER','mailstats');
	define('DB_PASS','mailstats');

	# connect to local DB
	$db = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4', DB_USER, DB_PASS, array(PDO::ATTR_EMULATE_PREPARES => false, 
                                                                                                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
	#Get id parameter
	$start = time();
	#print $start;
	if (!isset($_GET["dt"]) or !isset($_GET["sn"]) or !isset($_GET["id"]) or !isset($_GET["co"]) or !isset($_GET["hr"]) or !isset($_GET["ca"]))
		die("All parameters must be provided");
	#Used in SQL - so must make sure no SQL injection can get in
	$dateid = $_GET["dt"]; 
	$servername = $_GET["sn"]; 
	$countid = $_GET["id"];
	#Not used in SQL
	$emailcount = $_GET["co"]; 
	$hour = date("Y-m-d:H",$_GET["hr"]*3600);
	$categ = $_GET["ca"];

	$SQL  = "SELECT *";
	$SQL .= " FROM LogData AS ld, LoglinesInCount AS ll ";
	$SQL .= " WHERE ll.Count_id =? ";
	$SQL .= " AND ll.servername = ? ";
	$SQL .= " AND ll.dateid =? ";
	$SQL .= " AND ll.MailId = ld.MailId ";
	$SQL .= " AND ll.dateid = ld.dateid ";
	$SQL .= " order by ll.MailId,ld.Sequence";
	
	#wh_log($SQL);

	$res  = $db->prepare($SQL);
	$res->execute(array($countid,$servername,$dateid));
	$rows = $res->fetchAll(PDO::FETCH_ASSOC);
	
	# Build up html for final print
	$meta = array();
	$html = file_get_contents("mailstats-detail-header.tmpl");
	$tablecontents = file_get_contents("mailstats-detail-table.tmpl");
	#Pull out meta variables
	$tablemeta = explode("@",$tablecontents);
	# every other one will be the metas (assuming no other "@" in string - so delete 2, 4th etc
	$tablemetas = count($tablemeta);
	for ($i = 0; $i < $tablemetas; $i++) { if (intval($i/2)*2 == $i) unset($tablemeta[$i]);}
	# and re-index
	$tablemeta = array_values($tablemeta);
	#wh_log(print_r($tablemeta,true));
	$i = 0;
	$numlogterse = 0;
	$meta["serveranddate"] = "No results found";
	$logdataids = array();
	$cntclassesused = -1;
	$Lastmailid = 0;
	foreach ($rows as $row){
		if ($i == 0) $meta["serveranddate"] = $servername." - ".$row["date"];
		#Remove tai64n number from front:
		if (substr($row["LogStr"],0,1) == "@"){
			$tai64n  = date("Y-m-d H:i:s",tai64_to_timestamp(substr($row["LogStr"],0,24)));
		}
		else $tai64n = substr($row["LogStr"],0,24);
		$row["LogStr"] = substr($row["LogStr"],23);
		if (preg_match("/logging::logterse:/",$row["LogStr"])) $numlogterse++;
		# now add to meta
		$dateid = $row["dateid"];
		$logdataid = $row["LogData_id"];
		$mailid = $row["Mailid"];
		#$meta["when$i"] = $tai64n."($dateid) - ($logdataid) ($mailid)";
		$meta["when$i"] = $tai64n;
		$meta["contents$i"] = htmlspecialchars($row["LogStr"]);
		#get cssclass for this id
		$connectionid = substr($row["LogStr"],3,4);
		if ($connectionid != $Lastconnectionid) {
			$cntclassesused = ($cntclassesused+1) % $maxcssclasses;
			$Lastconnectionid = $connectionid;
			#wh_log("connectionid:$connectionid");
		}
		$meta["cssclass$i"]  = "cssclass$cntclassesused";
		# and write line back to html using those metas
		$tablemetas = count($tablemeta);
		for ($j = 0; $j < $tablemetas; $j++) { $replacetablemeta[$j] = $tablemeta[$j]."$i";} #Create the new metas
		$html .= str_replace($tablemeta, $replacetablemeta, $tablecontents)."\n";
		$i++;
	}
	$html .= file_get_contents("mailstats-detail-footer.tmpl");
	$meta["hour"] = $hour;	
	$meta["categ"] = $categ;
	$meta["secs"] = time()-$start;
	$meta["now"] = date("Y-m-d g:i:s");
	$meta["counts"] = "$i records $numlogterse log summaries ($emailcount)";
	$html = apply_meta($meta,$html);
	#Remove all tabs and newlines
	$html = preg_replace("/\t|\n/","",$html);
	#and add in newline for each row 
	$html = preg_replace("/(<\/tr>|<br \/>)/","$1\n",$html);
	print $html;
	$db=null;
	#wh_log_close("done");
	?>
