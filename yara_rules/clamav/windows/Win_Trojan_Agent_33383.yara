rule Win_Trojan_Agent_33383
{
strings:
	$a0 = { 6ca1ea38e3dbfba033eb2632ac18e0c3f4616e5f50eb2f2237af00bb5c2a64b2e7e28888591ad204c148e2f13422e640dd6f490edc1c9a91053d6d369e8ca2474c42a27ae6b78f3dae069da9053dcf203bf019a98ccedfa1b641c044 }

condition:
	$a0
}

        
