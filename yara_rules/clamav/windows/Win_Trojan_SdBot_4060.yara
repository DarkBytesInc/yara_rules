rule Win_Trojan_SdBot_4060
{
strings:
	$a0 = { dbce85c1dfab16f24f1d61be3816b4d9413b85b1ff3d420794669a50d714547ddeb0f3a881aa1f0717a30a79213b9bf191f3cc1d8206cdfcd8dbf8cfe36ae242c3f79a959925291dc943b6b9bfa9c0a433e4e3d7186a }

condition:
	$a0
}

        
