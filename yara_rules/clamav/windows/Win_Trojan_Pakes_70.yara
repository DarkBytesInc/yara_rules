rule Win_Trojan_Pakes_70
{
strings:
	$a0 = { e25cfc30effe369ca0304dc9f67d07e2aeef1f95112899800e9ddfcb33941454fae87acb061c46610fccbd420c26d0e7d5d6a08e265d3a8dd77f3602fdc994335bdb20f03472c9dec2401f4844992eeac8a50979313443db523c5debaa856feae2adfca71fbbf443bec04eabd23bacd7d91154cff97a0b34cb098340e4 }

condition:
	$a0
}

        
