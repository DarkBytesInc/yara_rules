rule Win_Downloader_Agent_32273
{
strings:
	$a0 = { 5d0cd70376234bbd4c40b116dc05e2b802fecdb604119c1ffc97fe49885c322dbeceb0fffdd26c0faaf3270769ab6de4c2e60f04fed331485f63476e670d2b08fe00fed7076c672b051a31090c80109c6cb561280b51f6e43f06245680e21180e156c6f2585f14dc28cd0c65aef54f145ec248878feeea7a4ce467f44c869d3e2080c24279bea89ade1adea8231cb974ede555a2 }

condition:
	$a0
}

        