rule Win_Trojan_SdBot_4138
{
strings:
	$a0 = { 31faa0387a8cea8bc5de46f744708d30241e8b53fd3b7636bfaf1da1b1fbf8b7e017bab4ea696d24c97bdee3da18d28cfdaf61cce66ecc5e1b19460bd9552de613ac97619cfbe5ff18c673c4301283ac57d5263386b2a03f2287a9bbeee551801ae227c4c38aa5b8e8f9e36144b57a2cc7a9e6613ebc04edab28fe0551e08ec7 }

condition:
	$a0
}

        
