rule Win_Trojan_Bancos_799
{
strings:
	$a0 = { 40811c920069c8d0000000000d3dcd5b8900579fffdbf4c9fefaf8ec1f0bf92040f738e86e36a9075d7d063300000000bffb80778278afa300d477ca96600ac824024833bbbd }

condition:
	$a0
}

        
