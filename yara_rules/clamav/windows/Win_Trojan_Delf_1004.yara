rule Win_Trojan_Delf_1004
{
strings:
	$a0 = { 30842d6955000b56d64991384abfed033753fe3de4cff3446cbbf81b1f9b39245f99a96e9661808bc2045ff5214b5de0452939d73b54af577e771c4dc4edb87cafd8b366786b447c919f71726365a1820792424e11cbc3f4d054a775a36aaae57861d7d40941e5878448f53bcb26644e5d13442fe115b385f6bebb3d1c1abdbd2ad2a0c87aca1938b801ceb72d920226f2938c87be63 }

condition:
	$a0
}

        