rule Win_Trojan_FM_2
{
strings:
	$a0 = { 2d000081e91b0183ea0083c20089ff89d2268a02346488c989c026880205000080ef004689dbe2e5 }

condition:
	$a0
}

        
