rule Win_Spyware_Banker_2392
{
strings:
	$a0 = { 78be46f925b37e3beecd410a0056b6a8c94731959d1b60d6a687d3b7c0fe15e00c7f5a0167584bf21f10ba5e115c386595614c8a47cfe457893cb62b39d498728c4c89ae2d3cbd274478f004a51ae74f3d2619e7ed782d7c111ff75039496be94d4a492273b405cf8da37148cfb627137c1ac487ec5cdb8392442e77edcf54a6 }

condition:
	$a0
}

        