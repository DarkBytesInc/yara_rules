rule Win_Trojan_Renos_26
{
strings:
	$a0 = { 88feffff29d001d081e8001a00008b95c8feffff1b9544feffff2b9504feffff81ea00130000ff8d00ffffff299580feffff019554ffffff2b8500feffff138554feffff85d2731db8fb000000118544feffff09d0402b8584feffff81eae800000083c2 }

condition:
	$a0
}

        
