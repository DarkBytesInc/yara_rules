rule Win_Trojan_Hacdef_31
{
strings:
	$a0 = { ccc45ab547d9475b6adb2f122b7f20b12195794d3e8dd99ea4cd048d7bb7bbb7536d2b0e4b5413bafc0e8912da5aa76ae56a2f86abb6e129191eee8ce7437c3d7ea579ac21cb3a0515cf60f3fb071947dec0155ac546ba3ff432b0c3 }

condition:
	$a0
}

        
