rule Win_Worm_Mofeir_9
{
strings:
	$a0 = { 01f611ee420b7c2dfe89747c6003ceac6961978eab6db431590c06dc42f8d9c908dca33708308581830ee08b168955d68945666f691604dc0e515405683056cf68b4c5bafb7b421e090a0f8e68af5fe48d8b9a2833dbbbd0f124979550ff54c7840db4d3a86912647be34eba1515d802de7334474cd14826507b62dcc0da2ce5257ed5a10892ac0d8ca6955d0c05325fe89a89c3966a }

condition:
	$a0
}

        