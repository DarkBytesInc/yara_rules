rule Win_Downloader_24567_1
{
strings:
	$a0 = { 558bec6aff6828114000683444400064a100000000506489250000000083ec585356578965e8ff15a810400033d28ad48915106c40008bc881e1ff000000890d0c6c4000c1e10803ca890d086c4000c1e810a3046c400033f656e8fb0000005985c07508 }

condition:
	$a0
}

        