rule Win_Trojan_FormatC_86
{
strings:
	$a0 = { 0a4563686f20666f726d617420433a202f71203e3e20633a4175746f657865632e6261740d }

condition:
	$a0
}

        
