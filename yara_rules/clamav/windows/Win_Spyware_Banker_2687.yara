rule Win_Spyware_Banker_2687
{
strings:
	$a0 = { b7fa63a2fe3b3d9683904f1ab5ad6cb84bf13799c7b3d2dfbaa172c223de431410843868b1968e972e066759240a3a4f3cea74b55519570c7e030068c861a2d46a156248ef5fdabdba3d53 }

condition:
	$a0
}

        
