rule Win_Trojan_Keylog_2
{
strings:
	$a0 = { 617364416363657074414847545951465754646e7361644666676a436c69636b }

condition:
	$a0
}

        
