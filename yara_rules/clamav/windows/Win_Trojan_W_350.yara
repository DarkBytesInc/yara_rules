rule Win_Trojan_W_350
{
strings:
	$a0 = { 60e8000000005fe8030500008db74b0000008d9e8700000033c08903895efcb8c1000100cd20900001008b54242083ea028954242066c742facd20c742fcc10001008997 }

condition:
	$a0
}

        