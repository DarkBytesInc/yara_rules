rule Win_Trojan_Amitis_16
{
strings:
	$a0 = { 58e8e320830d32fcf807f4c8801cd8f08fa9ec1dc8941cb0ece1941cc88037f0e8aa7b04caf0911010e81f60dfd07ac77210500b7b35434f574f4eaddeeaff204a65742d417564696f20c0696e57d6c999bbd52043dc73731f3b48c915c8d805377880c0 }

condition:
	$a0
}

        