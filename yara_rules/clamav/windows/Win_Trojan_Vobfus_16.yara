rule Win_Trojan_Vobfus_16
{
strings:
	$a0 = { 63756c616d656e746f736500000007000000ec48400007000000a448400007000000b43e400007000000703e400007000000083e400007000000c43d400007000000803d }

condition:
	$a0
}

        