rule Win_Trojan_Bancodor_5
{
strings:
	$a0 = { 257803ffbffdff433a5c0056578b7c240c33f657e80f093685c059766e8a043e8d0c3efeffffff3c617c043c7a7e083c417c253c5a7f21a8200fbed0750883c20d83fa5aeb06fdffbfc5071e0404f3eb02040d8801eb2b3c307c173c397f13ff }

condition:
	$a0
}

        
