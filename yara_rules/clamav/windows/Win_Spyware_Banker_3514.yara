rule Win_Spyware_Banker_3514
{
strings:
	$a0 = { fdfb3e070f2a1cca3cbe56dfd80084b6c197b5f568df5f1604a2b9a65b033b15d07e9ba38a518dba52973f229badc674cab52dc4c41f1c02a7c50ceedd0c9bf7c28649749d6b934399fca7215d5a50abcaa7fad6d301c8ee507a }

condition:
	$a0
}

        
