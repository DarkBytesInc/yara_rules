rule Win_Trojan_SdBot_3705
{
strings:
	$a0 = { c4aded7e0249096223ecbd650115bee3ba82eac37af0cfb74cf60e44727e730a77b7118286c5aa2d16eaf187de8eefeef7ff4120b491d0e29c35501a66dd590cdc19e08d81c7bf2ea8a27be018f461462b6fe1b79cbf0c9be4bf7ff0473c4c3a2462df8ebcc3f3be4b188fe78b6f }

condition:
	$a0
}

        
