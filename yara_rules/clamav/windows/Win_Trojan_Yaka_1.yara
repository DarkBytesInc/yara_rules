rule Win_Trojan_Yaka_1
{
strings:
	$a0 = { 690f416e74694d6163726f7356697275736469056e616d61240c67258005066467c28069056e616d6124076a0d3a41736c694175746f457865631269056e616d6124076a093a4175746f4578656312690b657865637574656f6e6c7964 }

condition:
	$a0
}

        