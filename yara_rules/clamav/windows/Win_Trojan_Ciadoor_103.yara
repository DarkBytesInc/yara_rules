rule Win_Trojan_Ciadoor_103
{
strings:
	$a0 = { 10ed5c3a6bf3502fde058d330e095d38a82af8268cc9447ecafbe3f181a23b7091de41f469a0b273c29d5ce4791b84ae82f752ee69522e98c6f5cc818ff22d60020f3bece2a8706992fe086e8dd9d0c06e36e143ac6a147c8e16934b6b6ebc5b461337920ee2e0a03604527a256ea5479563ba229a0a3139760693809ad3384192d28ea0cecb8bf749e1b840 }

condition:
	$a0
}

        