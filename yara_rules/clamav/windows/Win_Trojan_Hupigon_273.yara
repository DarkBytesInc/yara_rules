rule Win_Trojan_Hupigon_273
{
strings:
	$a0 = { c80c9d4628de5388f4c985812a2f9e6bfdc031df2e5f7ce60f07a213b9d2b22ed464afad30ef6f5732ac2de1c3c7e977eae89b48fa7f06a63a744703b271a857266bdbd27ee2377d85acfc04d532dc0df7be2eb006c70f79c2ef4407de2a856e138f691bac52ded327 }

condition:
	$a0
}

        
