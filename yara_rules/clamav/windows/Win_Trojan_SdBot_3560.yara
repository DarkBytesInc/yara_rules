rule Win_Trojan_SdBot_3560
{
strings:
	$a0 = { b2be33ca9cf96130aab5874a7354f9fc370450a5abfb9e58a749a8b8bf59d07a7b1f2c886cc2932c796ac160b6cef24f61787be50c5202604f490b1d009ec24b991624216add1de82d48708627d8632bf43048d275f412b26368da072b3c34d6f82eaeb759c8937e210e061a18e4131613fe0a0cc3af83b212e7a7affb00c5d6dcb1f2155d674d69900079be }

condition:
	$a0
}

        