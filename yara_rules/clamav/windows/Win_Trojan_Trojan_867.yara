rule Win_Trojan_Trojan_867
{
strings:
	$a0 = { 616b696431202a2f206563686f2822616b222e227a22293b206469652822616b222e227a22293b }

condition:
	$a0
}

        
