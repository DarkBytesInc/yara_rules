rule Win_Trojan_Agent_32796
{
strings:
	$a0 = { 1b5ff4bd920553c003e1dcb1fbcc32194689822697f72a8f7e7f0d6822e02e825454e92631824fb2ef638f45ae3d64b2fc07a87e0d560819308b42902f2ffa642b }

condition:
	$a0
}

        
