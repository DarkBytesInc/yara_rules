rule Win_Trojan_Pandora_3
{
strings:
	$a0 = { 6d2f616674657264656174687369787369787369782f706737637468756c752e6a7067006f70656e00005c00433a5c57494e444f57535c73797374656d33325c73687574646f776e2e657865006f70656e002d6c005c00200077696e696e69742e696e69004372656174656420627920 }

condition:
	$a0
}

        