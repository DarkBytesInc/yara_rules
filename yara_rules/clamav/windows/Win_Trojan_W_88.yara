rule Win_Trojan_W_88
{
strings:
	$a0 = { 4000598987a6010000b007e670e4713c047529b008e670e4713c07751f8d8fe10000008bf94f4780376675facd200300010033c0cd2003001700ebfe61c3eb06ff25fcffffff9c3d6e726f48750233c09d6878563412c3301e224827040f0109144a462e09140803024624 }

condition:
	$a0
}

        