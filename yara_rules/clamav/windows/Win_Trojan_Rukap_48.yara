rule Win_Trojan_Rukap_48
{
strings:
	$a0 = { 1d0809d043a9f4fc6de5faea3b206abb6c31b79d8c7879234f23f5cb4afe7acbb43e71d5584295468610ff61628123bb7e6f28ce484c241c40b69faf2052f67b88e17c288eab494c868c931c458edfbc3e018becb33c195538 }

condition:
	$a0
}

        
