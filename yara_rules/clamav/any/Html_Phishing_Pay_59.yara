rule Html_Phishing_Pay_59
{
strings:
	$a0 = { 3c62723e7765206172652063757272656e746c7920706572666f726d696e6720726567756c6172206d61696e74656e616e6365206f66206f7572207365637572697479206d656173757265732e796f7572206163636f756e7420686173206265656e2072616e646f6d6c792073656c6563746564 }

condition:
	$a0
}

        