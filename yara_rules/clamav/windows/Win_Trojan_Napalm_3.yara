rule Win_Trojan_Napalm_3
{
strings:
	$a0 = { 44008b03e8765fffff8b03bad0bf4400e8a65bffff8b0dbccb44008b038b15f0974400e86f5fffff8b0dd8cc44008b038b15d08c4400e85c5fffff8b0dc4cb44008b038b15b4954400e8495fffff8b03e8c25fffff5be8d876fbffffffffff0c000000424f2d424f20436c69656e74 }

condition:
	$a0
}

        
