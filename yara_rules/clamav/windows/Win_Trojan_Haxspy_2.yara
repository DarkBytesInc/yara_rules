rule Win_Trojan_Haxspy_2
{
strings:
	$a0 = { 558bec53565768500601006a006a006a15680c0601006a00ff7508e8320000000bc07526680c0601006840060100e825000000 }

condition:
	$a0
}

        