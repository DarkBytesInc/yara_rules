rule Win_Trojan_Perflog_25
{
strings:
	$a0 = { 2952309a??????9476796234247d????????4896????????4851????955f????2b19a6[0-2]a316??????9d55883b????0ae20e??ce0d0016670854c1f0817b }

condition:
	$a0
}

        