rule Win_Trojan_Jerkin_4
{
strings:
	$a0 = { 5f81ef080087efeb4e4920616d207468652043617463682e4d652056697275732077726974 }

condition:
	$a0
}

        
