rule Win_Trojan_Vundo_69
{
strings:
	$a0 = { d24424d0d38c24f3ffffff894c24b6eb0fd13637a40dc2d310090e2f3cc51a4b0f1e28eb0541e627d47de80000000068000000008f0424010c2468000000000934244952598d35ee4181000fc1f10fc1c9fc6800000000d38c24a3ffffff81ecfcffffff31b424fcffffff89bc24c4ffffffd28c24e6ffffffc68424e3ffffff4033b424fcffffffc74424f5 }

condition:
	$a0
}

        