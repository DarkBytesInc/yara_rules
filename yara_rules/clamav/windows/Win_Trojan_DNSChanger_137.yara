rule Win_Trojan_DNSChanger_137
{
strings:
	$a0 = { df16cc8cf709850211130a7d47f0c8e2f6fbace04a853a89df06e48cf70889a980cbb8c654828cd2ef8cc48cf7944810f785c417747a00886b02ade3fe85c410b7fafff6f9124bcdfc85c4df4ad64da5f6fbc08c6c72c4a22f97048d4785da4407c6c445 }

condition:
	$a0
}

        
