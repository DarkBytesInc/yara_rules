rule Win_Trojan_Shell_16
{
strings:
	$a0 = { 245f706f73745b27636d64275d3d226c73202d6c61223b207d206563686f20223c666f6e7420666163653d76657264616e612073697a653d2d323e222e246c616e675b246c616e67756167652e5f74657874315d2e223a203c623e222e245f706f73745b27636d64275d2e223c2f623e3c2f666f6e743e3c2f74643e3c2f74723e3c74723e3c74643e223b206563686f20223c623e223b206563686f20223c64697620616c69676e3d63656e7465723e3c7465787461726561206e616d653d7265706f727420636f6c733d31323220726f77733d31353e223b206563686f2022222e706173737468727528245f706f73745b27636d64275d292e22223b }

condition:
	$a0
}

        