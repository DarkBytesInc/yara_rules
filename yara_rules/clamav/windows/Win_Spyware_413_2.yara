rule Win_Spyware_413_2
{
strings:
	$a0 = { e65c4989c5ee5fece816d8628c1144a32c6971a9caa6af1f3e34474188b9df0bbdba6b73ed22a295d82da5670ddf8e0e0b727d626344930c577c000e7e0147d3f402f3843d3e074ce35ad6c7055f }

condition:
	$a0
}

        
