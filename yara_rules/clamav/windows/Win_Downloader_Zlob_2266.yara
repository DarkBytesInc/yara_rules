rule Win_Downloader_Zlob_2266
{
strings:
	$a0 = { 41bb9b444611bf3ee8e94e2ee81c4a139bc6921c3de953b3eff519470e2fd57a202f067bee3a00107ab7491fb66a45adcb2cdcef676bcbb8a6ffc60195f52702cc313f71e990b6adc206889ce3ee04e7a462eb398eb715ab962a }

condition:
	$a0
}

        
