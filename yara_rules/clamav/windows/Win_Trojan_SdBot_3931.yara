rule Win_Trojan_SdBot_3931
{
strings:
	$a0 = { f3b9bc4e1f8bc3e0efb7bbcdde6bb3d8ebb5ba4d9e4ba3d0e7b3b9cc5e2b93c8e3b1b84c1e0b83c0dfafb7cbddea73b8dbadb64b9dca63b0d7abb5ca5daa53a8d3a9b44a1d8a43a0cfa7b3c9dc6a3398cba5b2499c4a2390c7a3b1c8 }

condition:
	$a0
}

        
