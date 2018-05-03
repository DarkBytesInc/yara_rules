rule Js_Trojan_Obfus_73
{
strings:
	$a0 = { 666f7228693d303b693c6e2e6c656e6774683b692b2b2973732b3d73286e5b695d293b6576616c28737329 }

condition:
	$a0
}

        
