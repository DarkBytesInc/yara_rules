rule Win_Trojan_Agent_34725
{
strings:
	$a0 = { 5151535633f65668800000006a0456566800000040ff7508ff15403040008bd883fbff750433c0eb6f }

condition:
	$a0
}

        
