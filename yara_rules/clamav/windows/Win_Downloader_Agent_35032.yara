rule Win_Downloader_Agent_35032
{
strings:
	$a0 = { db969b9a981436e33f2b6b8bb854ba37cc77f7cd477da48b9ceda8d0b75bba908645ce96fbd58150aa9dbad4b7f9b9974145e294ff8a754447a2ba6f7da736e3bf8f59dc7845ed28b506eb969879a78bd757e1a404aafd91986df7da14ed }

condition:
	$a0
}

        
