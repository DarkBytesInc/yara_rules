rule Win_Trojan_RSBot_1
{
strings:
	$a0 = { 73746172742030333439306e632025310d0a30333439646e2025312030 }

condition:
	$a0
}

        
