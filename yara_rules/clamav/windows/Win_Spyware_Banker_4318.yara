rule Win_Spyware_Banker_4318
{
strings:
	$a0 = { 0063286ab0f76ae05e700d2da166de32f575516e40ee3c205b98f96ca5efe85fd557adbedb443d8bb31f22dbe2c3f3998d85c04c464fa3e0eaf5d19dc75e8f66612c4d985a710d5bad2cf35ff757505dadb64e452d0000d00ddcbf6efd7061640e21ef5096cd6908cdfdc315033b7cec23eeb00860d68ee3096ce421842a5e17d03c1b99987407d4d1effdcd }

condition:
	$a0
}

        