rule Win_Trojan_AntiWazzu_1
{
strings:
	$a0 = { 0100641b69044d41494e6467d7007301000c6a086175746f4f70656e127350010c6c000012730b00641a1b }

condition:
	$a0
}

        
