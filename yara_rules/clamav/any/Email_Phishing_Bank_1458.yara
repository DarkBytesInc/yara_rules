rule Email_Phishing_Bank_1458
{
strings:
	$a0 = { 466f7220796f75722070726f74656374696f6e2c20796f75206d7573742076657269667920796f7572206163636f756e74206265666f726520796f752063616e20636f6e74696e7565207573696e6720796f757220636172642e0a0a506c656173652075736520746865206c696e6b2062656c6f7720746f2076657269667920796f7572206163636f756e7420696d6d6564696174656c79 }

condition:
	$a0
}

        