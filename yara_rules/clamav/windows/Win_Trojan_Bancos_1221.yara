rule Win_Trojan_Bancos_1221
{
strings:
	$a0 = { e969e0cf9df8e442c184f1f31cbf9885495a2a2aa48df07bca75989eadc6118171b515c690c9ee558ce03023a1ca8d50e28c3becb5593ee6438dbcb16cec920a486ed6bd012f00a425bfe5504d748393e2e99bca3c5daf923728d5d48566e1 }

condition:
	$a0
}

        
