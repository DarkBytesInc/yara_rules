rule Html_Phishing_SPK_5
{
strings:
	$a0 = { 77617220756e736572652062616e6b206d697420696c6c6567616c656e207472616e73616b74696f6e656e2062657472[1-6]67657269736368656e2061727420fc626572666c[1-6]746574 }
	$a1 = { 646173206e65756520736963686572686569747373797374656d2066fc722069687265206b6f6e74656e20616b746976696572656e }

condition:
	$a0 and $a1
}

        