rule Win_Trojan_XRes_6
{
strings:
	$a0 = { 511e33dbb4809090cd2180fb80907503e9960033c08ec0bd8400268b46022ea39904268b46002ea397048cd848 }

condition:
	$a0
}

        
