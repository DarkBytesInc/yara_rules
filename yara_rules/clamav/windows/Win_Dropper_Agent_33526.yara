rule Win_Dropper_Agent_33526
{
strings:
	$a0 = { 3a971fb49f2d649b1b1fa0919806c1f764fba2b266c2914645fe7ccba7a6a34203d6812a62f2e7092939511fd598266da6f16e34d7e4534d861b86f3b8ec9dffefd153cbbd7c58a00a49dbb237510c3b7d3648e0 }

condition:
	$a0
}

        