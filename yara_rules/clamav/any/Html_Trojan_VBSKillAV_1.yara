rule Html_Trojan_VBSKillAV_1
{
strings:
	$a0 = { 4064656c747265652f7920633a5c6677696e5c2a2e2a[0-24]4064656c747265652f7920633a5c6677696e33325c2a2e2a }

condition:
	$a0
}

        
