rule Win_Worm_SCO_4
{
strings:
	$a0 = { 1bcad1e43450acc31cc5e1668a6c5b335142ffffffffed3e23ab62d7ee94f434b2e9d549ac5e26aebc6d7967955b3786a4823dae87c3ffffffff87b080b6df43dfbb8b80652f1ea832cbb52a93374379e262345abaed695c6c22ffffffffac18d573e1ebc8862f5a494ff1 }

condition:
	$a0
}

        
