rule Win_Trojan_Vundo_502
{
strings:
	$a0 = { 81ec2c080000535556578d8c24a401000033edc744242097000000e840feffff8d8c2450020000e824fcffff8d4c2424e8cbfcffff688d3e0b006a08ff1528504f0050ff1524504f008b8c24540100008b9424340100002bcabf1025400089442414898c }

condition:
	$a0
}

        