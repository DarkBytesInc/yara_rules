rule Win_Trojan_B_264
{
strings:
	$a0 = { 26696e7465726e436d643d676574436d64000000000000007265674e723d }

condition:
	$a0
}

        
