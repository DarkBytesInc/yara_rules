rule Win_Trojan_SdBot_4020
{
strings:
	$a0 = { b0cef98cdb007ddfdfd0cb8d865309e9ff1a0a445712c91f45a1247803f10f6169aa5b8483d48b48d4591ef67dfb1b14ac04cbc5988c6d4ff0dcde5066730b1047fb56cff46ae336f70f30172bfe2ecfdb4bf0173a75 }

condition:
	$a0
}

        
