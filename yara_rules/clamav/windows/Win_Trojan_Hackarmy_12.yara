rule Win_Trojan_Hackarmy_12
{
strings:
	$a0 = { f5d62099fecb8b42beeeeab228d9e3dc64117330bd62c3a1ef2f807efb9de095adf8e8a3a3fc6e023dd3ad146d5ba2c6bcb9cbcd48426a77d778f0a64771bfe28528dcf38ed386b679b1f1a1bd7afa4a21b42821b8cfa0ca0061d04ae42dd7450f2470fee0db249d4dcee63e705a0b87ffe6643a91b2ed5cf89c63982bc3b630 }

condition:
	$a0
}

        
