rule Win_Trojan_C99_19
{
strings:
	$a0 = { 6c6973742824757365632c202473656329203d206578706c6f6465282220222c206d6963726f74696d652829293b2072657475726e202828666c6f6174292475736563202b2028666c6f61742924736563293b7d7d206572726f725f7265706f7274696e672835293b204069676e6f72655f757365725f61626f72742874727565293b20407365745f6d616769635f71756f7465735f72756e74696d652830293b202477696e203d20737472746f6c6f77657228737562737472287068705f6f732c302c332929203d3d202277696e223b20646566696e652822737461727474696d65222c6765746d6963726f74696d652829293b20696620286765745f6d616769635f71756f7465735f677063282929207b696620282166756e6374696f6e5f6578697374732822737472697073222929207b66756e6374696f6e207374726970732826246172722c246b3d222229207b6966202869735f617272617928246172722929207b666f7265616368282461727220617320246b3d3e247629207b69662028737472746f757070657228246b2920213d2022676c6f62616c732229207b73747269707328246172725b22246b225d293b7d7d7d20656c7365207b24617272203d207374726970736c61736865732824617272293b7d7d7d207374726970732824676c6f62616c73293b7d20245f72657175657374203d2061727261795f6d6572676528245f636f6f6b69652c245f6765742c245f706f7374293b20666f726561636828245f7265717565737420617320246b3d3e247629207b696620282169737365742824246b29 }

condition:
	$a0
}

        