rule Win_Trojan_I13_10
{
strings:
	$a0 = { ed0301b83030cd213d13cd7455b82135cd212e899e97012e8c8699018cd8488ec026a103002d250093b44a1e07cd }

condition:
	$a0
}

        
