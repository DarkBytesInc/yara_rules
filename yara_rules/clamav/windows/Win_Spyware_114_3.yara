rule Win_Spyware_114_3
{
strings:
	$a0 = { 652d59c715d444fda1936cc9ebdfd7ba634f034fb3e5a2de2bc48a281d4570d364a8bb4f2773698ff0532d79c692ae7d56b3073ac6a0626e0eff0e7dbe371c853e4c5a2a93eda1fec96ef01f967d22111097a5ff603e5aff610715 }

condition:
	$a0
}

        
