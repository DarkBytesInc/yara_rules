rule Win_Trojan_Soraci_4
{
strings:
	$a0 = { 733d63687228617363286d6964286d79656e63737472696e672c692c3129292b696d6f643229 }

condition:
	$a0
}

        
