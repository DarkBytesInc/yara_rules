rule Win_Trojan_Agent_35774
{
strings:
	$a0 = { 6f6e65626c6f636b3d[0-8]28222575306330632575306330632229 }
	$a1 = { 7768[0-16]6e6774683c3078363030303029 }

condition:
	$a0 and $a1
}

        
