rule Win_Trojan_Pogue_2
{
strings:
	$a0 = { c8bd6280a3264380a3dc4dbdb3ef902681666fce61caed232fa84acb6255689c337ced749578dc9da27e58f7bbef902681676fce61caeb232fa8e25f65caeaba2da8e86091d680666ff7d7a2901c69666f9e25e9d6e182cc90d5927d5fbab4f14ac26227 }

condition:
	$a0
}

        
