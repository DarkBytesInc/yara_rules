rule Win_Trojan_NetDevil_9
{
strings:
	$a0 = { 247669636e616d65203d2024696e7b277669636e616d65277d3b0d0a2020247573726e616d65203d2024696e7b277573726e616d65277d3b0d0a202024736572766572203d2024696e7b27736572766572277d3b0d0a2020247061737377 }

condition:
	$a0
}

        