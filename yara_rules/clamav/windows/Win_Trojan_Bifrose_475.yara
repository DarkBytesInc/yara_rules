rule Win_Trojan_Bifrose_475
{
strings:
	$a0 = { 50e1a480439ec2c8d7fa1013d7e01be754a2b5140be79febdec694fbd06cf46a446d9c2a3b656271ac86e879b11549954fa53696cd6031e16ade6796c3483c837fb9d32aeee92c60f7c838d1b0b351f98f434f974ea1e4011aeb }

condition:
	$a0
}

        
