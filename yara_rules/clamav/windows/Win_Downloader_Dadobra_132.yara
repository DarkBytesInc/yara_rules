rule Win_Downloader_Dadobra_132
{
strings:
	$a0 = { 852053a7ff596cf740b2b82441efb0458e372ff4b2e67bb1a7ad5ede57725f231afd60f5fb1b62136ce59d7a04974379cb81576647672a16ccb5b9dacd42cba92f546ebec6a4a0832b38e1d28fbeb407e616b47626c11e72a315ad956cfdb1901adb9a3431dfabba998e0af7 }

condition:
	$a0
}

        
