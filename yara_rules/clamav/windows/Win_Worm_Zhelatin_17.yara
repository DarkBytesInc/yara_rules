rule Win_Worm_Zhelatin_17
{
strings:
	$a0 = { eb3848b91c8d0100ba0200?00?c1ca0b89d6c3ab50525183c8ff4005e5??400029db8b0829c05353ffd14093595a5801df83c71483ef19e2dac3e8c3ffffff52ad05??????0?eb03e2f6c351b95802000089d781c190010000e8b5ffffff59b8ffffffff }

condition:
	$a0
}

        
