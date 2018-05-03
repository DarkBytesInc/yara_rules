rule Win_Ircbot_Vibust_1
{
strings:
	$a0 = { 6b20633a5c446f5c4e6f745c476976655c4f75745c5669727573427573742e657865207d0d0a0d0a6e313d6f6e20313a }

condition:
	$a0
}

        
