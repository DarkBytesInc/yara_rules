rule Win_Worm_Hermes_1
{
strings:
	$a0 = { bb2101062718fcb6fc65726d65732e00627920676cbeffff2f1fffcc3132bb9c454b10b948acd45ae63f4647b1a7a29905fefffff80a16da4fb3253a79b82780123a4fad339966cf11b70c573c0083 }

condition:
	$a0
}

        
