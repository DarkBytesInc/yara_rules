rule Win_Trojan_SdBot_84
{
strings:
	$a0 = { 4840680bf00b19937010e77075342c540107669de46c932c503810e754ec4c9b6808800b9382796ce3f870979f34243c61df050b36827924401810282d5414249bc798ff0ce3eb9b0f0ff885d43c14748b904868f735747150287003701a21748b904868f7357471502870036803119b6808ff680d4c246c29108787343c640107075565944d6921999536682c2c07 }

condition:
	$a0
}

        