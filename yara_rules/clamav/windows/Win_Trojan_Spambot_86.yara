rule Win_Trojan_Spambot_86
{
strings:
	$a0 = { a5266ff13ac386ccd5ffffff4270e9440ac2a5c6a76caff68d0819f85bac2628477d10398ae441ff8fb0fe8b14276a94fab3c16fe472301c92e95effffffffa84dc0c839e8420a3e6571dbb9ae882c8e47a9e9641010bf9b804fdc5b21845effffffff6f207936434e8bb196ac1a }

condition:
	$a0
}

        
