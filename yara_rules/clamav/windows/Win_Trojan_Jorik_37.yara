rule Win_Trojan_Jorik_37
{
strings:
	$a0 = { 558becb8d97540008b7814b901000000891029ce83f8007c16890df07740008915bc7640008b780c66be9d00897014a328754000b8800000005057e81e380000b8bd7540008b4818bf6100000089700c8900a1c874400050ff35b4754000e8fb370000bfb5754000134f1821d0894708a10c7640006a08a13878400050e8dc37 }

condition:
	$a0
}

        