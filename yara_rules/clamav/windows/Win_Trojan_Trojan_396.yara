rule Win_Trojan_Trojan_396
{
strings:
	$a0 = { e3afba9ce3c7d5541d0f126f1343c92f0ee4b810d9675266bdd7fbde7aeac9627dee14df7e82e8599a0770c450a30d2a93acc8064d1ead69bda2dfd2212e0b4e7dbd09ed3dd7aba62f4d10a1d1cd97ee5606589f226bba4e95feb8725a46ee4ec4417b2f3e6e9141cef945a5f1dd6886c72d57666730fb98 }

condition:
	$a0
}

        
