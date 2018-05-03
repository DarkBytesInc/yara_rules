rule Win_Worm_Stration_439
{
strings:
	$a0 = { f4dd42ddcb52d00b782e6713514f94fed764be1b840c85faf1fd37b3e164bd4732db544c6dabe3f48c57380fd8e37d3e823c06bcb6366fce669eb7e312f2d89e8fbae4513878a62ea8874bb3af73593d }

condition:
	$a0
}

        
