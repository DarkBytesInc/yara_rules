rule Win_Trojan_Hupigon_883
{
strings:
	$a0 = { bd75067539ecbbea785361ba1b4faa02d1c4ce9f5d9307d9c48d311cb99ca41384153f7f1617b65926e04cfac7894a67b2c44b0da36bd2bd422d35efdb6779ce0b2b151c441ea81e43befa854c37cefd372527d5f7f66fd81ebdc14f27953d }

condition:
	$a0
}

        
