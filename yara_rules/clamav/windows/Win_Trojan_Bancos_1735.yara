rule Win_Trojan_Bancos_1735
{
strings:
	$a0 = { b728eb70a9f84da2e444b1c430c8c9d4a5b42a2a243599d505ba65ffe546f14ce10423485de5742abebb0b00fc783b0b1e318763cb72d0735518839b0e82203f6dadc512f76a }

condition:
	$a0
}

        
