rule Win_Trojan_Mybot_5648
{
strings:
	$a0 = { 9d45dd574b9844ad940f86fae38b7f88423975cd87e1c801e34e2a180e4ca4bfc42973118e79905a4d659737381958fada45a1c85c089d43b61d0e2055f2f18a3b46b35b49d2c5af3b75274239dfface280dc1f19d730c1df89dfe61ce5360a62eb10b5fd095a364c5978e4924685f457415e72244e5dec69fd3a41966a179958a55865fc93bf5b023025ccf }

condition:
	$a0
}

        