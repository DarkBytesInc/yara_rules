rule Win_Spyware_Ardamax_16
{
strings:
	$a0 = { 41007200640061006d006100780020004b00650079006c006f00670067006500720000004e006f002000700061007300730077006f0072006400200065006e00740065007200650064002e0000000000500061007300730077006f007200640020006900730020006e006f0074002000760061006c00690064002e00000000004b00650079007300740072006f006b00650073 }

condition:
	$a0
}

        