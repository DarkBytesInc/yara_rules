rule Win_Dropper_Agent_33523
{
strings:
	$a0 = { d08113b1b3feaf0ff3bb4fd895292e59ebc8a47c3ada1848c9a14c4d2f699855759db639f1894ee1b3434f5cf37ae20b2d9f8aa610b4e41900b040b26094364b4faf7e472983a579f8a6598ecb4acc1342cb1e66 }

condition:
	$a0
}

        
