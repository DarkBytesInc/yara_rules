rule Unix_Trojan_Agent_37066
{
strings:
	$a0 = { 53656e6420537065656421 }
	$a1 = { 3a4675636b20796f75722061737321 }

condition:
	$a0 and $a1
}

        
