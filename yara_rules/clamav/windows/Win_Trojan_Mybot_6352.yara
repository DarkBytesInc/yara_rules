rule Win_Trojan_Mybot_6352
{
strings:
	$a0 = { 3d37a70d7a1740e5039e02d51d1d94baadd0f4ab3215b6bcf3270359d942159f8f7f837f9ed609eaa6d0ba2c889b1743bd5f79310c7ac162c0491d135d13970d482130c0ec9ad2b47280e6230b3aef14156551396ea4c3a39f1d8d41dc4d677031bad7b8a7149dacf70a6a608fdeca22c04328d901c1450fcc438426d24069a61d3f0f8ae899340cbe4187316bcc9de5cde9d3395d3f }

condition:
	$a0
}

        