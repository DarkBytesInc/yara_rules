rule Win_Trojan_Hupigon_313
{
strings:
	$a0 = { c1f0710fde5d6c8e5e29684c76dae417df0f4344efb20902f17e0da18546b64f4ca572d5f1fc321c33048c95db02c5f94e31b6e492bb231dee332181fda00a52525cca1e6fd292b58f78b092a2251e38f1f4202ec3d5a8ef2e87faa4ccdeae510e08bb20d70b }

condition:
	$a0
}

        
