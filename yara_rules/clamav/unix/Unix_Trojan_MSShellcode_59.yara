rule Unix_Trojan_MSShellcode_59
{
strings:
	$a0 = { 31db5343536a026a665889e1cd80975b680a074dba6668115c665389e16a665850515789e143cd805b99b60cb003cd80ffe1 }

condition:
	$a0
}

        
