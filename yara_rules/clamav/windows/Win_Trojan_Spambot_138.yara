rule Win_Trojan_Spambot_138
{
strings:
	$a0 = { 1ffcff61b981d8369a65cd54b7e20177b1d544499de8ab0c02d7c506aeffffffff3f80f148905a067b6faaa30e52efd73523a262835e34f430356bb1d35026f0a1ffffffff875494a722b06dfad8ee0106a738cbc183394640a16a0ecfa9a54158c5fec74a3f1480ffe07525daa1 }

condition:
	$a0
}

        
