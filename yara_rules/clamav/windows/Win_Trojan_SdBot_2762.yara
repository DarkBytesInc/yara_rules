rule Win_Trojan_SdBot_2762
{
strings:
	$a0 = { af91c67a805fcae82e5a3e2a53292cc476e4144d9eba8528f968c0b6a311221e35ed431997509c96a268748c1acb466acdc2243f471b1ef7633eddf42b45f3afddaa2cd367621c015ea021002cf176f283fce23f075b2d6315c6a38d5f53b179fbfa301ef6ba212d1c8a6dfaff313cdcab6cd127eb1b01a33cad7ce6251eb0967508fa95116ef2ad6af8c11c8a57a135eabf409dbb64 }

condition:
	$a0
}

        