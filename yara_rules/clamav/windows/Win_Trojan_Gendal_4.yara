rule Win_Trojan_Gendal_4
{
strings:
	$a0 = { ff31559c0955b031c9ff45cc298d00ffffff81c1001a0000b8c106000021c1ff8d88fdffff018d84fdffff318d80feffff298558feffffff8564feffff094dd8298d6cfdffff098d4cffffffff8548feffff018514feffff29c01945ccff8d18ffffff29 }

condition:
	$a0
}

        
