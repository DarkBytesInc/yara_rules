rule Win_Trojan_Mybot_5531
{
strings:
	$a0 = { dd54588b5338273656a3369115288516c95e24219e00000000d204603dc54c2d87ef0e499de95071e7bfd4a6b83c71c25ea5b252cabfc5d11600000000cebf7557189e9523cdc91194d7f79646c6cb15372fd09f29b73717e684bb1f2600c0ed0f420df22daf5ba3251cbf2cdc75de38b734ef00000000d18f727fb49d1fd62c47745debc4f6c28d194325d232cb27f5cc61901af52f }

condition:
	$a0
}

        