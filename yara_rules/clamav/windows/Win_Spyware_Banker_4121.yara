rule Win_Spyware_Banker_4121
{
strings:
	$a0 = { 200a102350414647f0ac404201139fb921083bdaa976e7731bb9dee69fc3bfc23dee677242deee40b97bbc06ddc815f4906eac17b5bc915ac82bae405ae416eb920dae41af5c9056e4035b920b5c80dae407aee40bb77205dddc06dcb82ddeee57373bbffffffb7dff7cf9f7ef39e79f7cf3ef9e79ce7f7f9eff02306c8134a5db45a2cf63b0efc4487d0ffb }

condition:
	$a0
}

        