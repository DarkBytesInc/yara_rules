rule Win_Trojan_Sql_2
{
strings:
	$a0 = { 8cd80507008ed858a31c01a115012ea30001a017012ea202012bc08ec0bf8400268b1d268b45028ec0891e1101a313 }

condition:
	$a0
}

        
