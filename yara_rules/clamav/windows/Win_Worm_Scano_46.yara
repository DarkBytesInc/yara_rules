rule Win_Worm_Scano_46
{
strings:
	$a0 = { f694439c9febf1bcabee89ee4c2a629fb2327f22f6ec2d0ce515c166211dfacf1648f080549a8a6b43af32632ceaf71606fa9be4619430d566653e24c553cada7de47fb9cde2e7c59abf41846f416207fbf36a7b8f01d156f26999a42ccf8d751ad29219dd4c1b71c6d8f3d1c0ddae6be13737a4d197a57add7047d424306c8daf4d21b55a112be7646ad61ca8eef567 }

condition:
	$a0
}

        