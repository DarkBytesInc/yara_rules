rule Win_Trojan_Papras_5
{
strings:
	$a0 = { 688d2100006a37e88d000000558bec83ec206818010000ff15500001105068003c0000506a40506affff153800011033c9515151516a0450ff156c00011050e80900000090eb468be55dffd1cc558bec83ec308d4424046a2450ff7508ff154000011068b48c00108d4c240c8b41108b490850c1e90ed3e02bc159010424c1e1 }

condition:
	$a0
}

        