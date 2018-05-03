rule Win_Worm_Locksky_21
{
strings:
	$a0 = { 5ebdfcfef0860c8542450301c4ff86d137befc5146c4d3ff34be53febeb9eb7731befc3a0c4e876bc941038c4e91fdfe3411eb4431befc888e95e80fa3458e441911fc743da94cfd34be38c6c4c5400535be6a034604db513434fbe9f2bdfcfe }

condition:
	$a0
}

        
