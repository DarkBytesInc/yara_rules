rule Win_Trojan_Trivial_509
{
strings:
	$a0 = { 4e5a0000000000000000ba8303b44ecd21e81300ba7503b44ecd21e80900ba0003b409cd21cd20721dba9e00b8013dcd2193b440b98902ba0001cd21b43ecd21b44fcd2173e1c3 }

condition:
	$a0
}

        
