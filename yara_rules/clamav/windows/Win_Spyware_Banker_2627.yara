rule Win_Spyware_Banker_2627
{
strings:
	$a0 = { f38f509067304ed578abb95d9fe2d031ea49f7b3befbc5ab45f57ac23dafbf6e2c6d0a875e4c1dba4f057b404dde8011561a330dc3600d1cecf59f5dd9cbe3a1460a86bf9237f27093df1e48a12f14df8de4280f654a06633c1993920940499346be }

condition:
	$a0
}

        
