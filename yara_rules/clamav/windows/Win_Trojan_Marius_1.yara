rule Win_Trojan_Marius_1
{
strings:
	$a0 = { 2261737022[0-151]5f6367767370687466637430373d2274696e672e666922[0-13]3d226563745c22 }

condition:
	$a0
}

        