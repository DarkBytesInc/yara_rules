rule Win_Trojan_R_87
{
strings:
	$a0 = { 83c60283c702e2ec90803e6701017507909090eb5a9001b462cd21fc8ec326a12c008ed8bf0000b0018a253ac474069090 }

condition:
	$a0
}

        
