rule Win_Spyware_Banker_5543
{
strings:
	$a0 = { 1e733a8e24c81f91bb67eae08f8d795f5940ef994416e527ed47de14a1cf2bdd821004c37b8bbae16b7e99af8c8d8d92c7b1133a77f2995adc09e9c63223fe22d32871b49498d9fd5f3508cc0d20681bd460dc2a39cdc4d88bc0f903f82dbf51b38ec59bb309cf23e8b204ad4a57f8f74f9a18c47d859975152c769742f45eeda1b72cbf2797bbcf7648fabfcbb04a4392eab061222e }

condition:
	$a0
}

        