rule Win_Trojan_DNSChanger_156
{
strings:
	$a0 = { 5693aca6ca3455924795bc8f4603bd0c1b72ba18b7580ecd7a2426646fcb53640727e09f139492dfb554c0f2ada697913df9dc110f0806401752ff5a284281d1 }

condition:
	$a0
}

        
