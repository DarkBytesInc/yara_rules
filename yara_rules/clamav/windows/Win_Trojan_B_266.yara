rule Win_Trojan_B_266
{
strings:
	$a0 = { 2f004c004900560045002f0048004f00530054002e00700068007000[0-50]7400650073007400550070002e00700068007000[0-50]7300690067006e00650064002e007000680070003f006d003d[0-50]6f00720064006500720073002e007000680070003f00690064003d00 }

condition:
	$a0
}

        