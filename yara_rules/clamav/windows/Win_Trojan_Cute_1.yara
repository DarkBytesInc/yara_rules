rule Win_Trojan_Cute_1
{
strings:
	$a0 = { 456e642049660d0a617670203d2022433a5c50726f6772616d2046696c65735c416e7469566972616c20546f6f6c6b69742050726f5c6d6163726f2e617663220d }

condition:
	$a0
}

        