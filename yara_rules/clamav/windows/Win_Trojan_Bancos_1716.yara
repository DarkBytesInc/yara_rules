rule Win_Trojan_Bancos_1716
{
strings:
	$a0 = { 4d761a990486c4865d00121577259c5124be8a9b51a8f6527288dccb4f1dc2de14b1106e7ee7f59504ce09dc51246655df5101a216bbdd91aae629b57745b36969a967c8259bd107a6f92204d86cdad17a7c56a1c9a9889d1d9ac61788f260fa5b3c53252a213955e8bbbe382eec6ce3af220b5320482b94f619bfd506a5c54e42bc212409656ff6f7a10f44 }

condition:
	$a0
}

        