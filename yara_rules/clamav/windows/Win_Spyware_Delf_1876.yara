rule Win_Spyware_Delf_1876
{
strings:
	$a0 = { 9a7d0b5c5347f6ff4d728180d104c56a1595da5845b405b1550cd62804f11ddef8404b058a96aa0bf78a6d41c2467ee532d2b27d6cbb9f767fab3fedb66bdd5db6ed56fad81a888254d722ba8a62abd53e2ec6b65458094acdff9cb993806d57ddbf1fc977ee3ccecc9c3973e6ccdc99b9bcc1cc6902e66ddc58909bbd }

condition:
	$a0
}

        
