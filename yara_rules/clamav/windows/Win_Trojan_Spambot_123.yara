rule Win_Trojan_Spambot_123
{
strings:
	$a0 = { 43df4aabd61b11599a78bde1716a12f161ff09ad38a81fb1b6b65bfa8bff1d28579a3674f6783e5df1480091a4ffffff1f3fd393f4c8e8c704da10008c70bfba4a0af34cbf94a7dbdc94fdc91afff8ffff74575b7194746df353491105a936c94909de2cdb9e55661eb8c7ffffff }

condition:
	$a0
}

        
