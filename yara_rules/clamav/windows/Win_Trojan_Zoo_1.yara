rule Win_Trojan_Zoo_1
{
strings:
	$a0 = { 0600be1e02e8a400b92000cd217303e85801b90600eb06900000040000be1e02e88900e8aa00813e9a007f0176 }

condition:
	$a0
}

        
