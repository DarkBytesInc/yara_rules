rule Win_Trojan_Hacdef_61
{
strings:
	$a0 = { 69343f88ab460336933bc54f39d251d72ba05bf27f63073cdb9935e1f71287951ee95e9d7b251f7143b6ed3ee07fab0a694440ea9adab5203023767663a4b398dd859f225ad78ba74bbd0050916b64ea9fbc31d4168ce44ac014 }

condition:
	$a0
}

        