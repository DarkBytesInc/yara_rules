rule Win_Trojan_Perflog_35
{
strings:
	$a0 = { 311435080020000000696e73742e646174 }
	$a1 = { 3314350d0020000000737663686f737477622e646c6cff }

condition:
	$a0 and $a1
}

        
