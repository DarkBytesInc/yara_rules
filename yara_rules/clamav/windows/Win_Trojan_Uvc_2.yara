rule Win_Trojan_Uvc_2
{
strings:
	$a0 = { 0300b8a24bcd2150f7d050f7d850f7d050f7d83dd404585858587403e822008cd80510002e018641002e018643 }

condition:
	$a0
}

        
