rule Win_Adware_Lookme_38
{
strings:
	$a0 = { fdf765f4e5cea218d024b0f152e4d62befc2d33ea5a23dd9f62d1a6e148015afc3d7ed5e78f86dd21db58c698fffaf524bfa34ac0c367814b3ea2891ff184a77a136b199b77fa9baaa942f779e2c4262860bfc24d9430d9a2af8786480d16d3f100fb33adca533b899995ecf0c0a }

condition:
	$a0
}

        
