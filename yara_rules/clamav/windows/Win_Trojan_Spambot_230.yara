rule Win_Trojan_Spambot_230
{
strings:
	$a0 = { 8f57997daf1bfffffffff860a3e46b60a1976f392269ec2f14237053abbc8eb38fd49fc38093d955bf2ffefffff56a03955c4bc5f126b2a3996c0704d0e7ab2706e4bb0bcf5f08ffffffffdd3e489ba3ead1bc4a29a6b7004742a0d3431dbf163f2e314732f7d827eaecd9ffe1ff }

condition:
	$a0
}

        
