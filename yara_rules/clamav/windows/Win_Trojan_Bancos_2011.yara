rule Win_Trojan_Bancos_2011
{
strings:
	$a0 = { b268b0ce483b3e1f91757adea80c8b9dd90e9255e5c18c8ed3e05185edb0f7dce67b35cb60193a31290f6b2242ee93586746aced19c5f7679ac36d7df2cb379b11ddb67b1a6f371d0b35a3466be211bb754854275b1c06d03ab0b0820f09c08f268ecbe3d206e60f8aeaf8d4f50a }

condition:
	$a0
}

        