rule Win_Trojan_Small_3471
{
strings:
	$a0 = { 71e9c29f91651aec3f354426061ab05058ad3134e09d71a72c717d1f86d0d4327e58db67708edc95bc11dc70c19dd409156a0e8c2548869da76216f51fbbe2c02ddabb6eef4574a81ecfd7936058 }

condition:
	$a0
}

        
