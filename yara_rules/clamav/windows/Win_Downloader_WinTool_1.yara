rule Win_Downloader_WinTool_1
{
strings:
	$a0 = { ffe82498ffff33c05a595964891068b68001008d45e8e8579affff8d45f0ba02000000e86e9affffc3e95497ffffebe35f5e5b8be55dc20400005574696c4d69 }
	$a1 = { ff0900000057696e546f6f6c735c000000ffffffff07000000556e62 }

condition:
	$a0 and $a1
}

        
