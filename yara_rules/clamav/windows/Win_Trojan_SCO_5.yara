rule Win_Trojan_SCO_5
{
strings:
	$a0 = { 5661633742029effe66fff00558bec81ec6406a15633f6578b3da0568d45f86a01505b3b63ffff75088975fcffd70e040b04f8dfbefdddff1523983da29e3c1389180f8530010e8d859cfd9adb98fbff }

condition:
	$a0
}

        
