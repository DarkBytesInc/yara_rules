rule Win_Trojan_JS_276
{
strings:
	$a0 = { 5b226c2f6f2363236169742f69696f76[0-16]6b232f5d2f672c2222295d3d623b746869732e683d2222 }

condition:
	$a0
}

        
