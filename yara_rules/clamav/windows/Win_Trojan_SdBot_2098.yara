rule Win_Trojan_SdBot_2098
{
strings:
	$a0 = { 51fff0bf17b14a2490838ef7171c359d2a054223bbba2f37016dd9e1e986a09b7239bf2ec3394088674c6a292022202715993bb17053cef8da4f8a8debe7ab9bbe00ce246fcb02f7b415967d27df2be2d9e6 }

condition:
	$a0
}

        
