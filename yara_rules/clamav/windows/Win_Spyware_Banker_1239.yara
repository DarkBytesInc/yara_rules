rule Win_Spyware_Banker_1239
{
strings:
	$a0 = { 94d0153415e60115306c8a7f31356e444c624650d9f1a1d92c408d807b79a80ae1876319df482744b7c756aea5831161e65ab80201e9869b767d827d93fbcef67a35e8ff242c55a356ba5f91be601a7b271e51b6b9be80335416993d1a7efae496b98ab8 }

condition:
	$a0
}

        