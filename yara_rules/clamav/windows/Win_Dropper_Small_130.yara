rule Win_Dropper_Small_130
{
strings:
	$a0 = { 5004700b743b8cf80bd5203d207320275e201cb6d59f1b27303409434c9c4422f9b7ff7f7b31374441304339452d34413237046163352d4242370afbfe7f3544323442384344423937327d397d6e1a3140586c09e3089b152a3f36e4ab1b7dd8954e6f52446f76fc6bedb0586a7746232b18365b }

condition:
	$a0
}

        