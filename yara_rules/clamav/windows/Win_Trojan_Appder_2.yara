rule Win_Trojan_Appder_2
{
strings:
	$a0 = { 1d6907446967697443240c6a01331e6452670e81056a0e4d6963726f736f667420576f7264126a065645524d494e126a0131126a0c57494e574f5244362e494e490664646907446967697443240c678c81056c0a0006076a045c2a2e2a64 }

condition:
	$a0
}

        