rule Win_Trojan_PerfectKeylogger_6
{
strings:
	$a0 = { 15c04f400085c0761a8b4d088d85ecfeffff50e871fcffff8b4d0c8b0783450c04890153ffd68b45f8ff45fcc1e80283c7043945fc728ee9b40000006a4933f65933c08dbdccfeffff89b5c8feffff566a02f3abff15a44f40008bd883fbff0f }

condition:
	$a0
}

        
