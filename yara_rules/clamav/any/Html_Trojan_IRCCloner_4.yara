rule Html_Trojan_IRCCloner_4
{
strings:
	$a0 = { 29207b202e6e6f7469636520246e69636b204e696365207472792c2062757420696d206e6f7420676f696e6720746f207061727420746865206d61696e206368616e6e656c2e207c2068616c74207d207c2020696620282432203d }

condition:
	$a0
}

        