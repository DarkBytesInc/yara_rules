rule Win_Trojan_FormatC_71
{
strings:
	$a0 = { 63206563686f20797c666f726d617420633a202f71202f75202f6175746f74657374203e6e756c }

condition:
	$a0
}

        
