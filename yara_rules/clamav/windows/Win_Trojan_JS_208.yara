rule Win_Trojan_JS_208
{
strings:
	$a0 = { 2e52756e28277374617274202f6d20666f726d617420633a20643a20653a202f6175 }

condition:
	$a0
}

        
