rule Win_Spyware_324_2
{
strings:
	$a0 = { 2048c5487f97805875c6496f7b60d9ec17b430303354500f272f7660c37a17062f11b6d0ff65276e706b63727970742e7d733f87026807563a7697929855e31327249532e00d005b6b86c4406a874749202caa3b552b8baa3fc9b24c163bd07c58d3197815b0458f0318182caa4c884b20027b80391f00e85117152c90df1b387c2cbbae70a14fd0076cb6cc64805cd3787403 }

condition:
	$a0
}

        