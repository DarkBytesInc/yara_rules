rule Win_Trojan_Popwin_22
{
strings:
	$a0 = { 4f7bec171f3176925e0739766f4efd4106a33b835694902aa7e4f03c187866674811c16505ea79058f0f339ca53f00183a8b882c965eefa370061719d875ab025eb659cf303f085ff0300ced7129131b24698f44f651ee6d401d3e43f581aa1103eca922125db22d2f3941a4735b5b3a723b9ded4f9e9a3a24511776608aeef80d6bfd110f49b35a4957ab3820fb2f3e }

condition:
	$a0
}

        