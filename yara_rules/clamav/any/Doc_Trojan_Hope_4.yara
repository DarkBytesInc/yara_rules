rule Doc_Trojan_Hope_4
{
strings:
	$a0 = { 4f7074696f6e732e436f6e6669726d436f6e76657273696f6e73203d202830202d2030293a204f7074696f6e732e536176654e6f726d616c50726f6d7074203d202831202d2031293a204f7074696f6e732e566972757350726f74656374696f6e203d202832202d203229 }
	$a1 = { 4d43203d20434d2e4c696e657328312c20434d2e436f756e744f664c696e657329 }

condition:
	$a0 and $a1
}

        