rule Win_Downloader_11695_1
{
strings:
	$a0 = { 68000070632e7068703f34003c4120636c6173733d746974b8205a006c6520687265663d2269636b6782591869645f6b37b7003e81c720041474505881ef200414746a0087f7eb02fee2eb01c587f78104244f5a4000e804000000c2de90c0682f0763 }

condition:
	$a0
}

        