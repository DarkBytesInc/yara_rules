rule Win_Spyware_Goldun_108
{
strings:
	$a0 = { 63646673ecbac9fad9381258005c2d54cedd16741d73d7d1fa87602f6141de00408b04ad3b0172772844e45b0efc81e83b5e9a700248b2b7f9242375693820c283f5fbc2b7900d0a2d820334363730429be05c7b357b337b0c795f002fdbf6ffed25733f0f9e3d6e74a7485410502f312ee4190055de72fe5f }

condition:
	$a0
}

        