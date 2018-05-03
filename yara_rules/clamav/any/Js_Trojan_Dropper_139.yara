rule Js_Trojan_Dropper_139
{
strings:
	$a0 = { 2e7461726765742e7375626a656374 }
	$a1 = { 2822786f6f78 }
	$a2 = { 3332343233313334 }

condition:
	$a0 and $a1 and $a2
}

        
