rule Html_Phishing_Bank_683
{
strings:
	$a0 = { 6465617220[0-20]20637573746f6d65722c3c2f666f6e743e3c2f703e3c703e3c666f6e7420666163653d22617269616c222073697a653d2232223e74686973206d61696c20697320746f20696e666f726d20796f752061626f75742074686520696d706f7274616e7420757267656e742075706461746573206f66 }

condition:
	$a0
}

        