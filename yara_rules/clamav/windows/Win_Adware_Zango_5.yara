rule Win_Adware_Zango_5
{
strings:
	$a0 = { 52004500470049005300540052005900070054005900500045004c00490042000000484b43520d0a7b0d0a094e6f52656d6f76652041707049440d0a097b0d0a0909272541505049442527203d20732027534149496e7374616e746961746f72270d0a090927534149496e7374616e746961746f722e444c4c27 }

condition:
	$a0
}

        