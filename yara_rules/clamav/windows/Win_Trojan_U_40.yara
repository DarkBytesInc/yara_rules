rule Win_Trojan_U_40
{
strings:
	$a0 = { ffffffffe98a00000089f69068e43403008b45e8508b45fc50e87d2d010083c40c89c08945f48b45f485c07f02eb2c8b45f4508b45e8508b45f850e88b2d010083c40c89c08945f08b45f083f8ff7507b8ffffffffeb3cebb389f68b45fc50e8172d010083c4048b45f850e80b }

condition:
	$a0
}

        