rule Win_Trojan_Brepibot_2
{
strings:
	$a0 = { 687992a5ec06f4ecbd89dfb13f4073168b08ff85058b552acd3a9b7b94bdf80945e8a1b80d7cee1a0a91d04c8e698632d8b04fcc0f0080afc4b0efa3693205af05aa0b270e175a369c8c683a1165c8d4c9c01e3cab5b79b26cc816d012fe02fcfd43cb4e2dc011d0b91d0a580d0dd080 }

condition:
	$a0
}

        
