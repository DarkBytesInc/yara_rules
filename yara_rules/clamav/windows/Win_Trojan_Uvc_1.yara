rule Win_Trojan_Uvc_1
{
strings:
	$a0 = { 81ed0300b8b84bcd213dd2047403e822008cd80510002e018631002e018633002e8e9633002e8ba63500ea0000f0ff }

condition:
	$a0
}

        
