rule Win_Trojan_Mybot_131
{
strings:
	$a0 = { dcf13192889a01119916a12a7d51115f8a2d4929f23d10ba06c78e5264782a1c30e4684d8fba966e9b4a4f8cc59279eb1c55934b795b410d6e0b1e245cc2d4551c61e484a2d1ef85397f17b7d3a0d19158d1084b34b34c4b9a065816d1dc192d52e01abc86eaf28b1b }

condition:
	$a0
}

        