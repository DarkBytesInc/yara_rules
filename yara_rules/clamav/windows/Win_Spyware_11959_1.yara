rule Win_Spyware_11959_1
{
strings:
	$a0 = { 5e6a33fd84fed4e2adc972104b051b68c92b4915de408cde41ef6e168ca41ec69de0030cb9a01de84caa8afcbc5b856b01bd2acd7c5249e3aae503a4806f1f9261b1882b9dfc7b5228211b52450a4e0f57b8fa1d59283cca94b48464040f1bfb510a1089fa296a16335af80b7ce8ace144a7f07ca95f5a8c3fba843bb8f7422e0354550a6a063a44d74eba0d463608625cfd11f40105 }

condition:
	$a0
}

        