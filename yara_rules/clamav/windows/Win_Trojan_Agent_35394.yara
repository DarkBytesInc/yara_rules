rule Win_Trojan_Agent_35394
{
strings:
	$a0 = { 32c07406b935bf7fa315505083c404893424d3ce51518b74240883c40ce95105020056f7de5e0000 }

condition:
	$a0
}

        
