rule Win_Trojan_Hupigon_865
{
strings:
	$a0 = { 657434d9435fc742a0d3e119b7e4b3a8bbfbd72489bb7b9bbbe462010e5cf12502c8cd091446cb6f978b8ad4e537dd23c682dd97536ccd13c2f0b8a1ad506f586cf921694d5fd5cf05f77b10d23e943b4a903bda587edef804e810a7e2658f }

condition:
	$a0
}

        
