rule Win_Spyware_495_2
{
strings:
	$a0 = { 562d3fcf2c103ebd56823ff7152c3fbd41e7f342a9570037102d75fe572d3faab3e1c042f61b0317223e438659849728ac3a3282562da89cc7c6d32aa687d751415104bd56d90036ac3a8abd562da88ec7c6d32aa687d75141b9 }

condition:
	$a0
}

        