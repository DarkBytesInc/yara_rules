rule Win_Trojan_UCF_2
{
strings:
	$a0 = { 8836bc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fab155053efb8f6505c50067beec07ec07ec07ec0507decb8e8505650a29dcfc0be0242dac886ed780e5a2e24e6d63ee4ec9dcfbb0308b493560fedebce405751efea6e5023432dbe000156b98e01c704b93ac6440252813450ee46 }

condition:
	$a0
}

        
