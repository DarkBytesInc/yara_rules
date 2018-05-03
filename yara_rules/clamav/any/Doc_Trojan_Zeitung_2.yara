rule Doc_Trojan_Zeitung_2
{
strings:
	$a0 = { 436f6e7374205369676e6174757265203d202256697275735a656974756e6722 }
	$a1 = { 4b696c6c2022c0e4f1eae8e92a2e72746622 }

condition:
	$a0 and $a1
}

        
