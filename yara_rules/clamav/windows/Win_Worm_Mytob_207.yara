rule Win_Worm_Mytob_207
{
strings:
	$a0 = { 94823fe362bafde438cca23caeabe1c39903723ccbd941f671119bc8eabfb46d68e5ce976658dcca6b31f5da82199da31b3325268620729a5c2dbe1af6fbb198cca82aab831eb0a59b5b5f0e71ded3c2f3c4c566e6059561c3c88871bc7d0eb6ae49cf2ca50090653d9b2eacf49b3a80 }

condition:
	$a0
}

        
