rule Win_Trojan_Agent_35964
{
strings:
	$a0 = { 558bec83ec74ff1560c14000894594e827070000000000000000000000000000 }

condition:
	$a0
}

        
