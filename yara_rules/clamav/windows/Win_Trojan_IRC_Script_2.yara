rule Win_Trojan_IRC_Script_2
{
strings:
	$a0 = { 7365742025626f742e6f6e6e6574206f6e }
	$a1 = { 662028256e69636b2e626f74203d3d20246e756c6c29207b206e69636b202472616e6428612c7a2920242b205f20242b202472616e6428 }

condition:
	$a0 and $a1
}

        