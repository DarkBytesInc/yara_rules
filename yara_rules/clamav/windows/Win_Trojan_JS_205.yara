rule Win_Trojan_JS_205
{
strings:
	$a0 = { 6a6a6171683d2864647974783e2e323433383f786b6a70763a332e29 }
	$a1 = { 6b68622b226964222b6862716d6d2b22656e22 }

condition:
	$a0 and $a1
}

        
