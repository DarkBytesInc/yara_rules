rule Win_Trojan_IRCBot_186
{
strings:
	$a0 = { 2e9275d276979fc22b930da58e226919e60648c0fc72b94018e722d65b37db65146650100ad231333f82003a7ea03079e0e2653f968d63cce8a6bae883c03cc6298bd475360c5195b7eaddeda66740496de58d30795700611e5b7e161d27cc2cb3e2b0b8a274c5504c5a88e436552b3117e4054d35e2acf53feaedb563 }

condition:
	$a0
}

        