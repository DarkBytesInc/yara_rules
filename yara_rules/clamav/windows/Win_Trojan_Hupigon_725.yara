rule Win_Trojan_Hupigon_725
{
strings:
	$a0 = { bd9e9a3b0ee71db54bf85085e80eee0c975cc8601933d3d0b3b71e585d01990a83d853efb1682583fce5e9d755c1ebec16169bed75fbfebbef81c656550e468edfa1e97656d5c41cd320faab3df1617fc620d1888dde164a }

condition:
	$a0
}

        
