rule Win_Spyware_Banker_2694
{
strings:
	$a0 = { 612ea6ef571f0153be7a922f677ecf7eb61472e704644c50e88132bd6ad2867ad2e19c9117bed719a68978f17f514e2f4deb9f590537b4ac599965cef6ec4ec384e40f112ab43f11ce3ba769a1e7 }

condition:
	$a0
}

        
