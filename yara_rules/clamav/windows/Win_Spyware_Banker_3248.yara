rule Win_Spyware_Banker_3248
{
strings:
	$a0 = { 65740472ffff8000c08b4926782d7fff58794204d75b17d974f9e1b40057036472ffd3829ee0806143086910cbd70400056cc016a0eb987453060a6772f4c0e2b2ec00b0b0e3ef04403afce13ccfc33b080c1004384c9c1780e768a4624f54077463656af86f9ca7b20762ec0b1c80bb060074737953035c47146d111849490a0f727c9f007f6e6563616601 }

condition:
	$a0
}

        