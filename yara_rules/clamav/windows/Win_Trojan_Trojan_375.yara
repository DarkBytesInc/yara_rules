rule Win_Trojan_Trojan_375
{
strings:
	$a0 = { cad52c0c6b07ba0adc370050415254afbf50029ad3700a4a4f494ed7ac6a8ba36f6ace0f025ebfb86b054d4f4445110f6d174a680c650f72a00261497759e9195b41c3705bc4a56aa6 }

condition:
	$a0
}

        
