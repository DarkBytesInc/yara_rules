rule Win_Trojan_Bancos_1174
{
strings:
	$a0 = { 4b6213a736e23738692d460e08df5e61ad6fa4f0d81ef698d48c445baa2c40d4f0260c15b29e4a018ccb567805de445ad3192d24f0f7f1d12f2460c2f4aa23592847d605d0d9bb54ee7b4df5c2eaa0aef54c21590fe5ac7c3f0c }

condition:
	$a0
}

        
