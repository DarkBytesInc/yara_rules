rule Win_Trojan_Mybot_7249
{
strings:
	$a0 = { bf6e99c7e6bda81a35fdc62a88647f490d7b706629a953648560cd0a193e70d0eaab474a77653e19593e0f53552684b848ccdbc47b714ce4cd8ba675ee4482ca45f56e925f557ddf3631629aa0f4 }

condition:
	$a0
}

        
