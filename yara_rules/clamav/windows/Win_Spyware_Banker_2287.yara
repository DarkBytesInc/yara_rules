rule Win_Spyware_Banker_2287
{
strings:
	$a0 = { 1f098ae48bbba0dc9b2f83dc56cf8e224616a55256d74f7ada7725b6c037cc1d29d1862afb80d5c748ef28abae1dde87f1abb79f74b282fc6d81124ea8f10cb577ff0f44215d4e20bc26949126a2bb95b424b4228bdf3c1e18ce615c1c96f549d6d68052109391c64c0f1b271ea264c667a9a9ffa3791d05a04fd8785982f9ea1f9c45eefbbb976d054268f8b43f }

condition:
	$a0
}

        