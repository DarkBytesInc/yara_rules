rule Win_Spyware_553_2
{
strings:
	$a0 = { 36421b906abc2dd87180af785c3893cca23bdbe4c0911374ad348f0d93f85a371e7789f004eeac303b902930872156fabe7ac8bceec8f3066ef130e5b2333feda209377c9a5f72a187b9fe45ee7f }

condition:
	$a0
}

        
