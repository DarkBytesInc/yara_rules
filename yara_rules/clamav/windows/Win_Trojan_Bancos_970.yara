rule Win_Trojan_Bancos_970
{
strings:
	$a0 = { f29b7ed8b92f19ca0deb4ed7e7e55c3748b55c1ebd824e67befde1936669aac9d44a5d9b00f6998c0114424b7f861566ffaf8f04122ecf160e3e72bacadcf46f4d0ec02eb89be820ffd967d464e44eb0db012c8accc94152 }

condition:
	$a0
}

        
