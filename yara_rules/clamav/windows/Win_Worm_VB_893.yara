rule Win_Worm_VB_893
{
strings:
	$a0 = { 8c009d9d9d9d986028449d9d9d9d949034089d9d9d9d88409c649d9d9d9d187074509d9d9d9d1484483020169e9d3c80682c13e887c5c10c010001d53000806a46aaf6b6c8ad82a24b84f779be85382cae16d27dab011c007801b0580750726f6a6563743100c19c85eb85d8c0ffcc00000000006f53745bb1fad8498e1ea2313b3d0b64c818154d0db1674c }

condition:
	$a0
}

        