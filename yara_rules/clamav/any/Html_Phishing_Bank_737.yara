rule Html_Phishing_Bank_737
{
strings:
	$a0 = { 6e6c696e65206163636573733c62723e70726f7465637420796f7572206f6e6c696e65206163636573732e3c62723e3c62723e706c6561736520636c69636b20746865206c696e6b2062656c6f7720746f207570677261646520796f7572206f6e6c696e6520616363657373207769746820746865206e6577206669726577616c6c }

condition:
	$a0
}

        