rule Win_Spyware_Banker_6149
{
strings:
	$a0 = { b47fb13ac83dafd985e3bdfaf83175fc17c518c1da38e466b1bda6d059d8b5a3edc8feced3eab718172c769d7a657a5dd1d957985e72a4fde2f7722dbfb0935e724148bd24d6087ccbab3a39aeeebdfe55a637ec38f0c5ea0d87de08a5db626dc43699426762f39ddf437de114e399f08be9 }

condition:
	$a0
}

        
