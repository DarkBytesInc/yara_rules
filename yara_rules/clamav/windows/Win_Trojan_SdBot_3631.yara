rule Win_Trojan_SdBot_3631
{
strings:
	$a0 = { dc2777c577354e4fda4de24da77739201173a512a8477254e226b16e1b6cbc1b2b9babefb5a40f7d65bbe17b27868c43330cada60017ea10c27b09c3d5c9203bb10ac2e1c904dcc8347b128f69db }

condition:
	$a0
}

        
