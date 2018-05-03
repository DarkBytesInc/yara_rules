rule Win_Worm_Spybot_10
{
strings:
	$a0 = { 2e645d556dec456c54045c73060e1a79a5014688d257e9ff455c4b415a4141d55c4ce213c1b5155bcf32ef333435a7132f0b3734384bc733 }

condition:
	$a0
}

        
