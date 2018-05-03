rule Win_Tool_Agent_436
{
strings:
	$a0 = { 2e7430b80103b90900ba8000cd13bf3600be367cb9ca01f3a426c6069e0101b8349026a30100 }

condition:
	$a0
}

        
