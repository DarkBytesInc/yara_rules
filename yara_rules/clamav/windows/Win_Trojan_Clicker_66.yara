rule Win_Trojan_Clicker_66
{
strings:
	$a0 = { 55545dff25066140005329dbff254330400055545d83ec10ebef8a9c28f4feffff81ff00010000e921feffff5050ff25df614000568bd9ff1538634000ff3598304000ff2500624000568b3d473040005057ff2566304000598d7db0ff252b6140005150 }

condition:
	$a0
}

        