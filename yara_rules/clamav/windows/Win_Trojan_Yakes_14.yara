rule Win_Trojan_Yakes_14
{
strings:
	$a0 = { 558bec81c480fdffff565753508d84248000000089400c5068000100006aff6a006aff6a00506a00ff1510406a308d54 }

condition:
	$a0
}

        
