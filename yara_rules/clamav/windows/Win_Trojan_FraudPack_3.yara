rule Win_Trojan_FraudPack_3
{
strings:
	$a0 = { 558bec4e03da8bcf4b4f2bca414b8bf1e8ecfeffff747474748f4424f44b8bc84633d72bda33da0bc28bcae8c8fcffffe8e8ffe8ffe8ff748d6424048bce4ef6df2bf12bf80ae98ada8bfa02efe879fdffff7425e8ff25ff8d6424044f2bda2bd98bf7424f8bf1e874feffff25e8257425e82525891c24f25b4233d103d90bd9 }

condition:
	$a0
}

        
