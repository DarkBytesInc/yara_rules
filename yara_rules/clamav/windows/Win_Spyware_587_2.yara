rule Win_Spyware_587_2
{
strings:
	$a0 = { 0f592549f27b0df30c0af4e58f876cc2f45cb9d457fb30e48d90a8f51aeddef2a59cbea05afd20ddc00ece95826fafb5a14109f6aed09cdeca3b665c9660392f11e9a52c6abfab93eec2a4b70beb3a0d9bec9c9df6ead4c47ced57c84f3f9126c9e57c28215a2197a92ae53fa9d9a841d8816afc32f0 }

condition:
	$a0
}

        
