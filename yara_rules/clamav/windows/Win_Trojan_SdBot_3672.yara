rule Win_Trojan_SdBot_3672
{
strings:
	$a0 = { 2cca088dab187686626a298452fe5c08f0b6d10da558e224a5c228570b8a0cc40f18905e71ccc437c723b0ce76442cf8bdedb658fa0126e4974a6b56038183eed367bac197be036d0c80a9e6d9f8 }

condition:
	$a0
}

        
