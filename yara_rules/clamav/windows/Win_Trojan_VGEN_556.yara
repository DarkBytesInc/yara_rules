rule Win_Trojan_VGEN_556
{
strings:
	$a0 = { 1e9049424d20504e4349000201010002e000400bf009001200020000000000fa2bdb8edb8ed3bc007cea2f00c007cd }

condition:
	$a0
}

        
