rule Win_Trojan_Delf_2012
{
strings:
	$a0 = { ef6880c76ecc9e5ba6c5f974d00a09d7b91a40a9fbd44037dab9459b7c73425158798db4ef2af34ff6674d8fb0fde827269030bd4ccf6d0ff03aecc237a40ed900a354fb5d78e8ee67c076f3b593242ffa1dda2a592f78f9b6d3332eaa791ef95ba47a598c0772b0dab7ffb333ec5c5e024c5431f0c273ae798d3efddbc69db87de57ad2a1d21e8a231da3b6 }

condition:
	$a0
}

        