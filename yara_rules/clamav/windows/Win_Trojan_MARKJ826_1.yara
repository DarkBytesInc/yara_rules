rule Win_Trojan_MARKJ826_1
{
strings:
	$a0 = { 3a030000b801d60000be430800c0e886000000c705860400c04d75726b8bc72d420400c003053a }

condition:
	$a0
}

        
