rule Win_Joke_Jep_1
{
strings:
	$a0 = { 44008b038b1514d14300e83cdcfeff8b03e8c1dcfeff5be88b44fcff000000ffffffff1000000049742773206f6e6c7920612067616d6500 }

condition:
	$a0
}

        
