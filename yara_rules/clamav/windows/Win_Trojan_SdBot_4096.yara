rule Win_Trojan_SdBot_4096
{
strings:
	$a0 = { e26e8b0c8a48659aafb09876c864c5873f2338b9e5a2af1ca8d2d0d41dd69ffcd63318ebd513db66e6a59c863ac19b7147b32b3f541d04b0cf4a74a3485506db7f855e9f18f734ceffe03f669b2be407a3a80cb2fabb61f2158aaceef0c1bba8373f6797de63c765a3a0b59a5ebee2cfe20c1cdbe3f664fe0b5e3bd74a8cde74 }

condition:
	$a0
}

        
