rule Win_Trojan_Ace_11
{
strings:
	$a0 = { 3c2540204c414e4755414745203d }
	$a1 = { d7d60d0a23407e5e3478634241413d3d402340263f6e4d5c7f4452556d4d7277444b723a7f573b4f7b2c2c }

condition:
	$a0 and $a1
}

        
