rule Win_Trojan_Agent_32805
{
strings:
	$a0 = { e7941f6d5222037fcc38e9360ddb36be9ce003a3cefff73262328d1e90970dc18e168c8dccfe0b01c8d4b256afd44d2433cf5d998e9116221e722e67c4df31ffe862bfb48aa07427bec2d075eebae4e1d0bd6eb306d6691f9567 }

condition:
	$a0
}

        
