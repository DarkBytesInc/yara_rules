rule Win_Trojan_Banbra_55
{
strings:
	$a0 = { 208127100133622123185c72777f7876161601c00a030f4f696b756000577074657280115683d0faf3b59d958111c5e0c31279a8e8c4e084e5ebb18cb2b4b25e580006afd8d95828ab0c92304088cc83a2a1a0b6c71880619b3179c867c8125fb7f0c8c1840120209bc9f2eeff996bac2c01340883c9e8cb85b5e58782 }

condition:
	$a0
}

        