rule Win_Trojan_SdBot_3812
{
strings:
	$a0 = { 4c4ee5ed95cc0c6d445f18e3084520ffba9a33105452b98af9ecb077f3426ce35189ac61f75e638ad698a5505eab4b346c21f69c2930ff293f3250b5f3cbab17110c78abdeba2c1b24ec0f8dd5235366b0d4c113e7e5f690cbf8e8e7e4c09e544fb9 }

condition:
	$a0
}

        
