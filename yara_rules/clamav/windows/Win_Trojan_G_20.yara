rule Win_Trojan_G_20
{
strings:
	$a0 = { 03b8d701cd133d474d7515e9f3014f7273616d202d204d61646520696e204f5a8cc0488ed81eb8c000bf120029 }

condition:
	$a0
}

        
