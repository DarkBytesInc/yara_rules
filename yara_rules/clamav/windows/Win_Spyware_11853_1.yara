rule Win_Spyware_11853_1
{
strings:
	$a0 = { 558bec33c055686359400064ff30648920b8f0614000e805d7ffffb8ec614000e8fbd6ffff33c05a5959648910686a594000c3 }

condition:
	$a0
}

        
