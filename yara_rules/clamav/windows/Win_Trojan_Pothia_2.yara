rule Win_Trojan_Pothia_2
{
strings:
	$a0 = { 558bec81ec9804000068d8c641008b450850e83a27000083c4088945e8837de800751d8b4d085168c4c64100e89725000083c40833c0 }

condition:
	$a0
}

        