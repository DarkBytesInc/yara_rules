rule Win_Trojan_Ciadoor_199
{
strings:
	$a0 = { 6069c0ffb3bfd67c403a3d6ab955a85dbda2786b767e859320c0eea507bfaca6633c5fea6dcc722ecb018e13bf3d98abe4374b3e9306707706f981c4b1c447f7c85812a2017b03b63f6b9684abc6d7b56ffea1f98b9d28aac481a4cdbd2e5953abd3539e }

condition:
	$a0
}

        
