rule Win_Trojan_SdBot_3933
{
strings:
	$a0 = { 8381a04018080200ffbfbfcfdfebf3f8fbbdbe4f9fcbe3f0f7bbbdce5fabd3e8f3b9bc4e1f8bc3e0efb7bbcdde6bb3d8ebb5ba4d9e4ba3d0e7b3b9cc5e2b93c8e3b1b84c1e0b83c0dfafb7cbddea73b8dbadb64b9dca63b0d7abb5ca }

condition:
	$a0
}

        
