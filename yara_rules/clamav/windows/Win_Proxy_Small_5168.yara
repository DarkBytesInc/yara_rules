rule Win_Proxy_Small_5168
{
strings:
	$a0 = { 83fe0b5f33c05e818b07a44dc4c38b94243052660e7501a2180200897c241c20b0168b853d24668916e40960588d0850687e660480f213e902d76a108d4c51e13dfd7b28346276e0890c502c512630d67b5424202c179f84246f5c6c1e74243c382ce0f92f167f13305f83c8ff402f4ad98d0852513dd99c0016f52dd0d75f8bc6cc66812c00b84810e86670 }

condition:
	$a0
}

        