rule Win_Adware_Virtumonde_40
{
strings:
	$a0 = { e896b3e99db8f6abc10f11ac1754313667c0943d6e0147172af8091a06106b3533c0aff528f0c8c0a70710b00304bef828830b5466ef4a827ba4224446be5dc21d62caf6e30c81d2f5baa85e7acce24cbec8dfffadc74f739f0905bba13a05a9543818f131950d0be05afc36ca2499a5f853ae028fe93d9be32d58f22c41ea7ae9a226264085586d93b5 }

condition:
	$a0
}

        