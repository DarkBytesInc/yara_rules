rule Win_Trojan_Dropper_141
{
strings:
	$a0 = { 6844154000e8eeffffff000000000000300000005800000000000000f3bb3cfe8609ed4f999ee26888a3488b00000000000001000000000000000000653165656561663732393932626266376663393561373037663963373831636300ffffff12d4108400000000ffcc310000f83fd21219bfb94ea6b7d835d172504f5576b3 }

condition:
	$a0
}

        