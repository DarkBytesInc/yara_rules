rule Win_Spyware_Banker_3992
{
strings:
	$a0 = { 41420454107d24742b102840226f5b81083ce554b799ccc6f73bdce9f877f08f7b99dc90b7bcc80e5ef603cbcc815f4dc1b560bcaddc15ac82b5c815ae405eb920dae41e3c72415b900adc901ae405ae40be9916f397205e76e11b7b705b7bdc6f7fffffdfeff7cf9f7eeb5e79f7cd7df3cf37bfdfe7bfc08c9b204caadda2d167b1d877a2243e87fd39c051 }

condition:
	$a0
}

        