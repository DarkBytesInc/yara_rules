rule Win_Trojan_VGEN_231
{
strings:
	$a0 = { a200bf73018135141047474a75f7fc10144d95fd011199a6d711ab101547b1b4d296bf1215a40e9d829016dd359d82 }

condition:
	$a0
}

        
