rule Win_Trojan_Popwin_47
{
strings:
	$a0 = { 61646472706f7000706f7077696e00006465736b746f70007469746c650000006661766f72697465730000006473666664736731322e737400000000267665723d0000003f6d61633d0000006d65636f75 }

condition:
	$a0
}

        