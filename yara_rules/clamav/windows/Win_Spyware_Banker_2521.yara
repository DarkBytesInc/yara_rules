rule Win_Spyware_Banker_2521
{
strings:
	$a0 = { c01b489f7d3ba07a2e8cff8d2b551c8ba2a456ceba3cd13a73db572aa80c94713e6d947199db34cce2664a5f38501769570e02afb69b2b7649fffdf6df057eb1e0b362852480949dd1daf3b70b9b2ac0affd20c80a3c05c301a1419172340a1b3d454cd3f827d99cbaec88325ae15585912e81615dab90659c2a8be9d0e0c5d14e89204491228f0bc4d94b8a }

condition:
	$a0
}

        