rule Win_Spyware_Banker_2437
{
strings:
	$a0 = { 3935cde1954bd3094df729b3d681e9b9d8a0686a83a4fcfa79798fc0e17e5f3df770d89a5eda86d090e64f55f36a315b7b93a18db6d826b219887c4e4e95cf2752834c83c3c6964f0e4c }

condition:
	$a0
}

        
