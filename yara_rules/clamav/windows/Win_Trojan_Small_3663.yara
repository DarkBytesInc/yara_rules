rule Win_Trojan_Small_3663
{
strings:
	$a0 = { ed74a162256e20d7caade7f1737ae7f1737ae7f17375a385e774ab85eb7458e5a35e639ba55e5feb24eb97e5a35f4bb56d038a211ec466f6a332b284a4ade7f1737ae7f173759b85e7751fecf32adb3358f1e07123 }

condition:
	$a0
}

        
