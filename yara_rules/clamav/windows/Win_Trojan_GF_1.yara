rule Win_Trojan_GF_1
{
strings:
	$a0 = { 33c08945f833c08945f4a0541344008b55fc3a42287412c745f8010400008b45fce8510000008945f48b45fc0fb64028508b45f8508b45f4508b45fc8b400450e8d6eaffffa0541344008b55fc3a4228751a33c08945f08d45f050687e6604808b45fc8b400450e85feaffff8be55d }

condition:
	$a0
}

        