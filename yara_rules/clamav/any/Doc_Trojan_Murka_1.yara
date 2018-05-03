rule Doc_Trojan_Murka_1
{
strings:
	$a0 = { 274d75726b61202d20ddf2ee20f1e0ecfbe920ece0ebe5edfceae8e920e8e720e2f1e5f520e8e7e2e5f1f2edfbf520cce0eaf0eec0edf2e8e2e8f0f3f1edfbf520eceee4f3ebe5e9 }

condition:
	$a0
}

        
