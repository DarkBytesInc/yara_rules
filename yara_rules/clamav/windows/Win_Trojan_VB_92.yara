rule Win_Trojan_VB_92
{
strings:
	$a0 = { 38002d004600300042003400340042003400420044003200410043007d0000000000100000004d00610078005300700065006500640000000000200000005c006d00610078007300 }

condition:
	$a0
}

        