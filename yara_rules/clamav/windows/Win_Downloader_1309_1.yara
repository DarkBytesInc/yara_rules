rule Win_Downloader_1309_1
{
strings:
	$a0 = { 13cd49a1c00549e43b84fc1e2206fd9b066d5753758b1f47be732237ffa6f923286d064817d72b382e32000c9af48ef37c10307ed1e5fa59f8a1a6d72dc9ee7df3f25dc7ffa3975b4f41bb7d74a1e09afcebb27f8e0de266ba19e881e358b67e3df0108d31ad }

condition:
	$a0
}

        