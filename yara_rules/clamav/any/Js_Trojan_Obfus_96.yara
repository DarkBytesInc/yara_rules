rule Js_Trojan_Obfus_96
{
strings:
	$a0 = { 763d646f63756d656e742e637265617465746578746e6f6465282261736422293b766172206e3030303b666f72286920696e207629696628693d3d226368696c646e6f6465732229793d765b695d2e6c656e6774682b313b792a3d323b61613d646f63756d656e742e637265617465746578746e6f646528226576616c22293b653d77696e646f775b61612e6e6f646576616c75655d3b6528737472696e672e66726f6d63686172636f646528 }

condition:
	$a0
}

        