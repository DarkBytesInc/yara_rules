rule Js_Trojan_Blacole_10
{
strings:
	$a0 = { 77696e646f772e6576616c28737472696e672e66726f6d63686172636f6465283130352c36312c34382c35392c3131362c3131342c3132312c3132332c3131322c3131342c3131312c3131362c3131312c3131362c3132312c3131322c3130312c34352c35332c35392c3132352c39392c39372c3131362c39392c3130342c34302c3132322c34312c3132332c3130322c36312c39312c34392c34382c35302c34342c35302c3531 }

condition:
	$a0
}

        