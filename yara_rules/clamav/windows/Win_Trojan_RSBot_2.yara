rule Win_Trojan_RSBot_2
{
strings:
	$a0 = { 73746172742030333439306e632025310d0a30333439646e2025312031 }

condition:
	$a0
}

        
