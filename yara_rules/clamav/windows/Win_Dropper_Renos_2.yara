rule Win_Dropper_Renos_2
{
strings:
	$a0 = { 68????????68????????e815000000[21]608b6c24248b45008b5d04b920000000ba2037efc689c689c7c1e604c1ef0531f701c789d6c1ee0b83e6038b34b58410400001d631fe29f381eab979379e89de }

condition:
	$a0
}

        
