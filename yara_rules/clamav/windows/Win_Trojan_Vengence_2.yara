rule Win_Trojan_Vengence_2
{
strings:
	$a0 = { 8ed8ba6801b44ecd217259ba9e0089160202b8023dcd217245a3fc01b800578b1efc01cd21723d890efe01891600028b1efc01b9fc008b16020283c262b4 }

condition:
	$a0
}

        
