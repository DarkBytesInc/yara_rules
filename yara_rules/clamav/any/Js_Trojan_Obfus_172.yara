rule Js_Trojan_Obfus_172
{
strings:
	$a0 = { 243d5b355d3b7a3d2b243b6576616c28737472696e672e66726f6d63686172636f646528 }

condition:
	$a0
}

        
