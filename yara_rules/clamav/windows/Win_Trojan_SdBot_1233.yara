rule Win_Trojan_SdBot_1233
{
strings:
	$a0 = { 909173070c78dec12ee204110a33d40f808159b6e53f4d4420434b464445430a464647c56eb0f6434103e30e037c7b016e01b14243804748494a4bff36f01f3b4e4f5051525354c158595a617ffcf1ff62636465666768696a6b6c779bbc59727b75767783ff74f078797a308533ef363738392b2f3484a6befc5356576681ec89e6e8eded5544c3fe0912d663160dfa67a279f6af00 }

condition:
	$a0
}

        