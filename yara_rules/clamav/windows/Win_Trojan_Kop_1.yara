rule Win_Trojan_Kop_1
{
strings:
	$a0 = { dedfbbc4b6db929e9691bbb0ddb6d7b4b0afb6baadbab1bbc2dadab82d5fdab8285fdad9d9d3b3c1dfd9dcdab8275fdab8285fdad9d9d3b6d79bb6bab1acabbeb8d9d9c1bb8db6d8afbea6b3b0bebbbbc5c2bbc5c4bbbbc4b6d8afbea6b3b0bebbbb8db8f45fdab5d88fbea6b3b0bebbd9bbc5c4 }

condition:
	$a0
}

        
