rule Win_Trojan_Agent_32839
{
strings:
	$a0 = { f1ff211f3d47e5547e035c0d10246a578f55846829a0a9b9109be6b578ac3ec1e266904f3690b3c713ea8f420078ab871f1cbbf205239f1f76e9301962dde4a36b }

condition:
	$a0
}

        
