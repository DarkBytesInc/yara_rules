rule Win_Trojan_R_85
{
strings:
	$a0 = { 83c60283c702e2ee90803e4804017506909090eb5390b462cd21fc8ec326a12c008ed8bf0000b0018a253ac47406909090 }

condition:
	$a0
}

        
